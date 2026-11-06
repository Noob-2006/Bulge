# Hermes Agent gaps vs SE Agent: c627ec8466 → 90d6b98fd8 (2026-11-01 → 2026-11-05)

Read-only research, done 2026-11-06. Upstream: `hermes-agent`. Ours: this repository.
I read files and used git log/diff/grep only. No upstream code was run.

**Scope of the upstream delta.** 1,867 commits, 2,475 files, +114k/−41k lines. Most of it falls outside our product:
- **Desktop Electron app:** `apps/desktop/**`, about 70 new files.
- **Community plugin catalog:** `plugin-catalog/*.yaml`, about 153 new entries. That is 96 `feat(plugin-catalog)` and 18 `feat(catalog)` commits.
- **Contributor email maps.**
- **Lockfile/pnpm churn.**
- **CI consolidation:** 13 workflows were merged into `repo-guards.yml`.

Only about 60 of the 176 `feat` commits are product features. The fix commits are mostly hardening, concentrated in these areas:
- `agent/redact.py`, about 40 commits
- approval detection, about 15 commits (mostly PowerShell/wmic)
- checkpoints and `/undo`
- bot-mode/group chats
- the Webapp/dashboard auth

Status legend: **missing**; **partial** (what exists, with path); **have**; **N/A**; **unverified** (I could not confirm either way).

---

## Top 10 worth doing (ranked for a self-hosted, Linux-first SRE/ops agent with governance)

1. **Drop a safety-refused turn so the session cannot lock into a refusal loop.** Status: partial. The kernel ends the turn on `StopReason::Refusal` (`crates/seagent-kernel/src/kernel.rs:1081`), but the refused exchange stays in the log. The provider filter judges the whole thread again on every later message. Security and ops content (exploit analysis, malware triage) is where this bites. Effort S–M.
2. **Make compaction keep uncertain claims as `UNVERIFIED: <claim> — <basis>` lines.** Status: missing. Our summary headings are fixed to Goal/Progress/Key facts/Files/Next steps (`crates/seagent-kernel/src/compaction.rs:8`). During incident investigation, a hypothesis that hardens into a "fact" after compaction is a real operational hazard. Effort S.
3. **Expand secret redaction to cover connection strings and similar secrets.** Status: partial. We only mask token prefixes and PEM. Upstream also masks:
   - ODBC/ADO/libpq passwords
   - `PGPASSWORD`, `MYSQL_PWD` and `SSHPASS`
   - URL `user:pass@` userinfo
   - PGP, PuTTY `.ppk` and `age` keys
   - Azure `AccountKey` and SAS values
   - quoted YAML secrets
   - `--password`-style flag values

   For DBAs and sysadmins this is the most common way secrets leak. Effort M.
4. **Add a per-skill lock enforced on every write path** (skill tool, write/patch, and shell redirections into the skill dir). Status: partial. We only have the global `skills.write_approval`, which covers only the `skill` tool. The skills dir is even a `safe_root` for writes (`secgate.rs:304,384`). This is the governance control for "vetted runbooks the agent must not self-modify". Effort M.
5. **Require consent for every content-level finding in a command, not just the first match.** Upstream fixed a bug where `curl -F file=@.env … | bash` was covered by an already-approved pipe-to-shell rule, so the credential upload ran without its own consent. Status: unverified for us. `secgate.rs:654-658` grants by `(gate, reason)` or by the command allowlist for the whole decision. Someone should test this exact case. Effort S to test, S–M to fix.
6. **Explain silently auto-approved risky calls.** Status: partial. We write the label (`allow (always)`, `allow (allowlist)`, `allow (remembered)`, `allow (yolo)`) into the Gate event (`secgate.rs:654-667`). Upstream also attaches it to the tool result, so the model and user see why no prompt appeared. This is cheap, and it helps audit readability. Effort S.
7. **Harden checkpoints.**
   - Never snapshot home's parents or browser profiles.
   - Make the size guard ignore excluded paths.
   - Never stage the checkpoint store into its own snapshot.
   - Make `/rollback` after `/undo` keep the kept turns.

   Status: partial. We refuse only `/` and `$HOME` (`crates/seagent-kernel/src/checkpoint.rs:41`). Effort S.
8. **Recover `old_string` pasted with `read`'s `N|` line-number gutter in edit/patch.** Status: missing. Our 9-strategy port has no gutter strip (`crates/seagent-tools/src/fuzzy.rs`). This is a frequent model failure on edits. Effort S.
9. **Add an opt-in prompt-cache warm-up gate for batch sub-agents** (`delegation.prefix_stagger_seconds`). Siblings wait for the leader's first streamed chunk so they hit the provider cache. Status: missing. This cuts cost for fleet/batch fan-out. Effort S–M.
10. **Bound bot-to-bot chains.** Upstream adds a runtime hop counter (`max_hops`, default 4), refuses an identical ask twice in one chain, and makes replies notify-only. Status: partial. `agent_message` has an ACL (`crates/seagent-kernel/src/coord.rs:553`) and rooms have round/message caps (`crates/seagent/src/ops/rooms.rs`), but there is no hop count or dedupe across agents. Effort M.

Honourable mentions:
- Multiple-choice `ask_user` / clarify with native buttons on channels (partial).
- `/handoff` of a CLI session to a chat channel (missing, carried over from the old inventory).
- Importers bring in credentials only with an explicit `--migrate-secrets` (partial).
- OpenAI "Daybreak" Trusted-Access-for-Cyber flag on the Codex subscription route (missing; only matters if customers use ChatGPT-plan auth).

---

## Counts

These cover the 40 new-since-c627 feature rows below:

| Status | Count |
|---|---|
| missing | 9 |
| partial | 15 |
| have | 4 |
| N/A | 6 |
| unverified | 6 |

**Old inventory.** `docs/parity-agent/hermes-inventory.md` lists 315 items as missing (⬜). It is stale: it is dated 2026-11-03, and commit `1a1783c` (2026-11-05, +420k lines) landed after it. I spot-checked about 90 of those items by tool, slash command, CLI and module name. All were present by name except **`/handoff`**. This was a name-presence check only; I did not re-audit wiring or tests. GAPS.md (2026-11-03) said many of these were stubs at the time.

---

## A. New or changed upstream since c627ec8466

| # | Feature | Upstream evidence | What it does | SE Agent status | Relevance | Effort |
|---|---|---|---|---|---|---|
| 1 | Safety-refusal turn drop | `52eef32905`, `ab3afc0b89`, `6ec9d85795`, `abc8328801`; `agent/` refusal handler | A content-policy refusal soft-deletes the refused turn so later messages don't re-trip the filter; the turn is kept greyed for display and `/undo` is suggested | **partial**: `StopReason::Refusal → EndReason::Refusal` (`seagent-kernel/src/kernel.rs:1081`), mapped for OpenAI/ACP (`seagent-app/src/openai.rs:104`, `acp.rs:281`); refused turn stays in context | high | S–M |
| 2 | UNVERIFIED hypotheses survive compaction | `73bfb9ce7e`; `agent/context_compressor_prompt_rules.py` | Summarizer must emit uncertain claims as labelled `UNVERIFIED:` lines under "Unverified / Working Hypotheses" | **missing**: `seagent-kernel/src/compaction.rs:8` fixed headings, no stance section | high | S |
| 3 | Redaction expansion | `agent/redact.py` (+553), new `agent/redact_connstr.py`; about 40 `fix(redact)` commits, e.g. `5eb9cfb731`, `037b8da607`, `57f284e700`, `dc6149b22d`, `8e3321b871` | Masks key/value DB connection strings, `PGPASSWORD`/`MYSQL_PWD`/`SSHPASS`, URL userinfo, PGP/ppk/age keys, `AccountKey`/SAS, quoted YAML secrets, flag-passed secrets; keeps help text readable | **partial**: prefix-token and PEM masking (`seagent-security/src/risk.rs:548-583`), force-mode patterns (`seagent-kernel/src/trajectory.rs:101`), vault value redaction (`seagent-kernel/src/vault.rs:97`); none of the conn-string/userinfo/ppk/age/PGP/SAS rules | high | M |
| 4 | Per-skill lock | `tools/skill_lock.py` (new), `b694c7d907`, `91c51e04f4`; `hermes curator lock` | Locked skill: `skill_manage`, write/patch, and terminal writes into it are refused; the agent can't unlock | **partial**: global `skills.write_approval` / `guard_agent_created` (`seagent-skills/src/core/settings.rs:15,80`) and `pinned` (`usage.rs:217`); skills dir is a write safe-root (`seagent-kernel/src/secgate.rs:304,384`) | high | M |
| 5 | Every content finding needs its own consent | `8f6bb36594` (`tools/approval.py`) | An approved rule (e.g. pipe-to-shell) no longer hides a credential upload, credential pipe or invisible Unicode in the same command | **unverified**: per-gate decision; allowlist/grant short-circuits at `secgate.rs:654-658`; needs a `curl -F file=@.env … \| bash` test | high | S |
| 6 | Approval provenance | `tools/approval_provenance.py`, `468f14ac9e`, `f8950a11ed` | Silent auto-approval (allowlist, always, session) is explained in the tool result | **partial**: verdict label in Gate event (`secgate.rs:654-667`), `seagent approvals explain` (`secgate.rs:1262-1271`); not attached to tool output | med | S |
| 7 | Checkpoint hardening | `tools/checkpoint_manager.py` (+291): `201326cf58`, `af70d77be2`, `45bfd0ea40`, `8283794aa4`, `ada6384cea` | Never snapshot `$HOME`'s parents or agent browser profiles; size cap ignores excluded dirs; store never staged into itself; rollback never rewinds the store | **partial**: refuses `/` and `$HOME` only (`seagent-kernel/src/checkpoint.rs:41`); `max_file_bytes` and `max_files` limits (`:15`, `:194`) | med | S |
| 8 | `/undo` → `/rollback` pointer | `tools/checkpoint_undo_hint.py`, `tools/checkpoint_refs.py`, `8ea5add59c`, `9ea220e0e1` | `/undo` lists files the undone turns changed and names the checkpoint hash that restores them | **partial**: `/undo [N \| checkpoint id]` (`crates/seagent/src/slash.rs:141`); whether it lists changed files is **unverified** | low | S |
| 9 | Rewind picker (Esc Esc) | `hermes_cli/cli_backtrack.py`, `ui-tui/src/components/rewindPicker.tsx`, `1a71782f17`, `86be843ef5` | Pick an earlier prompt to edit and resend, or fork from there | **partial**: `/undo N` rewind, `/retry` (`agentcmds/retry.rs`), `/branch --at N` alias `/fork` (`agentcmds/mod.rs:70`); no interactive picker or edit-and-resend | low | M |
| 10 | "No, and tell the agent instead" | `86be843ef5`, `ui-tui/src/app/useApprovalAnswers.ts` | Deny an approval with a steer message | **have**: deny reason relayed to the model (`seagent-kernel/src/secgate.rs:904-907`, `seagent/src/term.rs:438`) | — | — |
| 11 | Stale approval card | `5ab58da1f6` | Channel button resolves only its own request id, not the next FIFO request | **have**: buttons carry `appr:<req.id>:<choice>` (`crates/seagent/src/ext.rs:891,1013`) | — | — |
| 12 | Dashboard CORS/WS origin tightening | `bd9328f969`, `cb837e10a5`, `0073fa98cf` | Only exact own origin or listed origins; no any-loopback-port trust | **have**: exact host match or allowlist (`seagent-app/src/exposure.rs:458`, `server.rs:223`) | — | — |
| 13 | Admin-managed keys refused at write | `ea52e2452c`, `c68c48301d`, `f19a64fd0a`, `8987ae565f`; `hermes_cli/managed_scope.py` | `config.set` / model pick / approvals mode refuse IT-locked keys | **have**: `/etc/seagent/managed.toml` `[managed] locked` (`seagent-kernel/src/managed.rs`); refusal wording at write time **unverified** | — | — |
| 14 | Delegation prefix-cache warm-up | `tools/delegate_tool_prefix_gate.py`, `6d0686ba3c`; `delegation.prefix_stagger_seconds` | Batch siblings wait for the leader's first chunk so they read the provider cache | **missing**: no match in `seagent-kernel/src/subagents.rs` / `agents.rs` | med | S–M |
| 15 | Bot-chain hop cap and dedupe | `agent/bot_chain.py`, `tools/bot_mode_dm_*.py`, `4e93f80e47`, `0754ec0e28`, `160339e0dd`; `gateway.bot_loop_guard.max_hops` | Runtime hop counter in the delivery envelope; duplicate ask refused; replies notify-only; fan-out with combined reply | **partial**: `agent_message` ACL (`seagent-kernel/src/coord.rs:553-561`); rooms bounded (`crates/seagent/src/ops/rooms.rs` header); channel `allow_bots=false` default (`seagent-channel/src/access.rs:66`); no hop or dedupe | med | M |
| 16 | Group-chat lead/auto routing | `gateway/hosted_room_lead.py`, `hosted_room_router.py`, `tui_gateway/hosted_room_router_call.py`, `4d85429c3a`, `57c6a9e44b`; aux slot `group_router` | A lead member or a cheap router model picks who answers; "Continue" past the discussion cap; room purpose and shared notes | **missing**: rooms use a fixed mention/rotation policy (`ops/rooms.rs:1-12`) | low | M |
| 17 | Cron delivery into a group room | `cron/scheduler_delivery_room.py`, `7fa5bbc71c` | `deliver: room:<id>`; posts job output into a room, and wakes only @mentioned members | **missing**: cron `deliver` targets channels (`seagent-kernel/src/cronjob/mod.rs:67`) | low | S |
| 18 | Cron hold across gateway drain/restart | `cron/dispatch_hold.py` | A one-shot that comes due during an update drain is not retired as missed | **N/A (unverified)**: our catch-up "fires once, not per missed slot" (`seagent-kernel/src/automation.rs:160`); no grace-expiry found | low | — |
| 19 | MCP consent line | `tools/connectors/mcp_launch.py` (new), `3dbb1303fe`, `f24a54c3d7` | Before approving a catalog or stdio MCP, show the exact argv, env names and cwd, masking only secret-named values and escaping bidi/zero-width characters | **partial**: `seagent mcp add` is an explicit user CLI action that refuses secrets on the command line (`crates/seagent/src/mcp_cli.rs:190-210`); no agent- or catalog-initiated consent card | low–med | S |
| 20 | Clarify with choice cards (Feishu) | `plugins/platforms/feishu/adapter_choice_cards.py`, `f94194ba73` | Native multiple-choice picker for clarify questions | **partial**: `ask_user` is free text only (`seagent-tools/src/agent.rs:60-70`); Feishu cards exist for buttons (`seagent-channel/src/feishu.rs:18-21`) | med | M |
| 21 | Slack `thread_followup_silence` | `53308b1947` | Unaddressed human replies in a bot thread may be silently ignored | **N/A (unverified)**: we default to `require_mention = true` (`seagent-channel/src/access.rs:59,66`) | low | — |
| 22 | Inline images in CLI/TUI transcript | `agent/terminal_image.py`, `hermes_cli/cli_inline_images.py`, `ui-tui/src/components/inlineImage.tsx`, `ab9dda55d6`, `e0d6efd4de`; `display.inline_images` | kitty/iTerm/unicode rendering of attachments and tool-result images (screenshots) | **partial**: protocol detection exists only for pets (`seagent-app/src/tui/pets.rs:420-435`); not used for transcript images | low–med (desktop-VM screenshots) | M |
| 23 | Paste collapse/expand | `ui-tui/src/components/pasteSections.tsx`, `domain/pasteExpand.ts`, `0ea7b3cf30` | A large paste is collapsed in composer and transcript and can be expanded | **unverified** (`/paste` exists, `crates/seagent/src/slash.rs`) | low | S |
| 24 | `/new` mid-turn backgrounds the old turn; parked notifications | `5d8e6fcd4a`, `gateway/run_background.py`, `tui_gateway/notification_park.py` | The running turn continues in the background, and its completion reaches the owner when it resumes | **partial**: `/bg <prompt>` (`agentcmds/mod.rs:71`); `/new` during a running turn and completion parking are **unverified** | low | S–M |
| 25 | Idle session retirement | `gateway/session_retirement.py` | The daemon drops idle live sessions from memory and restores them on demand | **unverified** | low–med (long-running `seagentd`) | S |
| 26 | Busy-arrival telemetry | `hermes_cli/observability/shared_metrics_busy.py`, `6f55623cc9` | Counts messages arriving while an agent is busy (queued, steered, dropped) and the daily peak of busy chats | **missing**: nothing in `seagent-app/src/metrics.rs` | low | S |
| 27 | Patch: strip `read` gutter | `tools/fuzzy_match.py` (+111), `f8bf10a2bd`, `320e5e352d`, `2fc589981d` | An `old_string` pasted with `N\|` line prefixes is recovered, never by similarity alone | **missing**: `seagent-tools/src/fuzzy.rs` (9 strategies, no gutter strip) | med | S |
| 28 | OpenAI Daybreak (Trusted Access for Cyber) | `60f5029394`, `agent/codex_service_tiers.py`; `agent.daybreak` | Sends `access_programs.cyber=daybreak_blue` on Codex-plan models listed for the account, giving fewer refusals on authorized security work | **missing**: no match; `openai-codex` provider exists (`seagent-model/src/catalog.rs:104`) | med for SecOps, low otherwise | S |
| 29 | Missing provider key named up front | `hermes_cli/runtime_provider_missing_key.py`, `894859c9fc` | Says which variable, profile and command, instead of a misleading 401 | **unverified** | low | S |
| 30 | Credential 401 recovery | `agent/credential_auth_recovery.py` | One forced refresh, then back off, for transient 401s (Nous) | **N/A** (Nous-specific) | low | — |
| 31 | Importer secrets opt-in; Grok Bot/OpenBot importers | `43cc73f12d`, `3053b9dd92`, `afc5c55d47`; `hermes_cli/setup_agent_import.py` | `migrate openclaw` imports secrets only with `--migrate-secrets`; new importers | **partial**: `seagent migrate` imports Hermes/OpenClaw/Claude Code/Codex and puts credentials into the vault by default (`crates/seagent/src/ops/migrate.rs:1-12,259`); no opt-in flag; no Grok Bot/OpenBot | low–med | S |
| 32 | Plugin unattended auto-update and "update all" | `hermes_cli/plugins_auto_update.py`, `5819226468`; `plugins.auto_apply` | Opt-in scheduled apply through the same scan/consent pipeline | **partial**: manual `seagent plugins update [name]` (`seagent-skills/src/hub/plugins.rs:787,996`); no unattended mode. Enterprises usually want pinned versions. | low | S |
| 33 | Published plugin public API | `hermes_cli/data/plugin_api.json`, `0502fe0597`, `scripts/gen_plugin_api_docs.py` | One list of the modules plugins may import | **N/A** (Python import surface; our plugins use a separate ABI) | low | — |
| 34 | Plugin catalog growth | `plugin-catalog/*.yaml` (912 → 1065 files) | About 153 community entries | **partial**: `share/plugin-catalog/index.json` has 704 plugins | low | S (data sync) |
| 35 | Memory-provider profile lifecycle seams | `e090092285`, `f02ba87b8c`, `14525b539c` | Providers get profile create/delete and config-storage hooks; forked sub-agents inherit the provider under `checkpoint_required` | **unverified** (`crates/seagent-memory`) | low | M |
| 36 | PowerShell/wmic approval rules | `tools/approval_detection.py` (+403), `3d4b6cfb93`, `cf4dfba6f8`, `267bf8faf9` | Gates deletes and Stop-Process inside PowerShell and wmic launchers | **missing**: no `Remove-Item`/`wmic` rules in `seagent-security` or `seagent-kernel` | low (Linux-first; relevant only for SSH to Windows hosts) | S |
| 37 | Context window "fallback" label | `2111815fab`, `agent/context_default_record.py` | When the context length was defaulted, the UI says so | **unverified** | low | S |
| 38 | `--cpu-profile PATH` | `hermes_cli/cpu_profile.py`, `a78e28d271` | cProfile of a run | **missing / N/A** (Rust: use `perf`) | low | S |
| 39 | glibc malloc arena cap | `hermes_cli/resource_limits.py`, `fcbf94c2e7`; `runtime.malloc_arena_max` | Bounds RSS of long-running servers | **N/A**: we link mimalloc (`crates/seagent/src/main.rs:8-11`) | — | — |
| 40 | Team Gateway relay account linking; Webapp "Web Access" | `gateway/relay/link.py`, `hermes_cli/web_routers/messaging_relay.py`, `17f52af6dd` | Link chat accounts to Nous's hosted shared bot; hosted Webapp start progress | **N/A** (Nous Cloud) | low | — |

Not listed as features:
- Desktop-only UI (Kanban tabs, KaTeX, mermaid, voice barge-in, Bot Chat UI).
- Nix and pnpm build work.
- `pm/` (uv package manager health).
- Docker s6 per-profile gateway supervision (`docker/s6-rc.d/profile-gateways`). It could matter if we ship a multi-profile container image, but I did not check our packaging.
- Video-gen Wan 2.7 (`c46c34cfcd`).
- The Discord libopus probe.

---

## B. Old inventory (c627) items still missing

`docs/parity-agent/hermes-inventory.md` (2026-11-03) has 315 ⬜ rows, which is now out of date. I checked about 90 of them by grepping our code for the tool, command or module names. Everything below is present by name:
- **Tools:** `web_search`, `x_search`, `vision_analyze`, `video_analyze`, `image_generate`, `video_generate`, `xai_video_*`, `text_to_speech`, `browser_scroll` / `back` / `get_images` / `console` / `cdp` / `dialog` / `vault` / `exec`, `cronjob`, `discord_admin`, `feishu_doc_read`, `yb_*`, `meet_*`, all `kanban_*` tools.
- **Backends and providers:**
  - terminal backends: docker, ssh, modal, daytona, singularity, vercel
  - browsers: camofox, lightpanda, browserbase
  - STT: faster-whisper, whisper.cpp
  - TTS: edge, piper
  - providers: bedrock, copilot, vertex, qwen/minimax/xai OAuth
  - other: credential pools, `key_cmd`, `llama-server`, MoA
- **Integrations and subsystems:** Bitwarden secret sources, OTLP, LSP, ClawHub / skills.sh / LobeHub hubs, batch/mini-swe runners, HF trace upload, wake word, realtime voice, achievements, disk-cleanup, security-guidance, OSV, verify loop, Teams meeting pipeline, Codex app-server, `/subgoal`, `/insights`, `/fast`, curator, bundles, journey.

**Still missing:**
- `/handoff`: hand a CLI/TUI session off to a messaging platform (`hermes_cli/commands.py:108`). Our `handoff` hits are `process action=handoff` (`seagent-tools/src/proc.rs:35`) and kanban, which are different features. Relevance med (on-call: move an investigation into the Teams/Slack incident channel). Effort M.
- `/rewind` as a named command (see row 9). `/rollback` is covered by `/undo <checkpoint id>` and `seagent checkpoint list|restore`.

**Caveat:** this was a presence-by-name check only. GAPS.md (2026-11-03) recorded that many such modules were then unwired stubs. I did not re-audit wiring or tests, so treat these as "exists", not as "working".

---

## C. Removed or deprecated upstream that we copied

| Upstream removal | Evidence | Our copy | Suggested action |
|---|---|---|---|
| Optional skills `notion`, `airtable` (replaced by vendor MCPs and vendor-owned skill taps `makenotion/skills`, `Airtable/skills`) | `8112254f8a` (2026-11-03) | `share/skills/productivity/notion/SKILL.md` and `share/skills/productivity/airtable/SKILL.md` (frontmatter `upstream: "hermes-agent/skills/productivity/…"`) | Drop them, or keep as unmaintained forks. Upstream also dropped `AIRTABLE_API_KEY` from its optional env list. |
| Optional skills `shopify`, `duckduckgo-search`, `searxng-search`, `honcho`, `mpp-agent` | `8112254f8a` | Not found in `share/` | — |
| `auxiliary.skills_hub` LLM slot; web_extract and session_search aux summarization | `8b1e49558b`, `a285c4f4ba`, `90c19e3196` | Not present (our aux tasks are approval, compaction, review, sampling, title_generation, vision) | — |
| `gateway/builtin_hooks` (empty package) | `9044ee16fe` | Our bundled hooks (`crates/seagent/src/hooks_ext.rs`, boot-md etc.) come from OpenClaw, so they are unaffected | — |
| In-process one-shot runner (`hermes -z` now always goes through the gateway) | `936f3465f8` | Not applicable: our one-shot runs through the kernel (`crates/seagent/src/main.rs:756`) | — |
| 13 CI workflows folded into `repo-guards.yml` | `d7244125e9` | Not copied | — |

## Unverified items (consolidated)

- Row 5: combined consent on multi-finding commands. This is the important one; it needs a test.
- Row 8: whether `/undo` lists the changed files.
- Row 13: wording of the refusal when writing locked keys.
- Rows 18 and 21: N/A judgements based on code reading.
- Rows 23, 24, 25, 29, 35, 37.
- Every part B "present" judgement is name-only.
