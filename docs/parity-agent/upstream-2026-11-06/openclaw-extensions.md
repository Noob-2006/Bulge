# OpenClaw `extensions/` delta vs SE Agent: 4e4342b9 (2026-11-02) to 8a186ad7ad7 (2026-11-06)

Scope: `extensions/` only. Read-only: git log/diff/show and grep. No upstream code was run.
SE Agent tree: branch `agent-parity-and-security` (includes 1a1783c).

## Size of the delta

- 364 commits touch `extensions/`; 1487 files changed (+48,266 / -12,313).
- **New extension directories: 2.** `extensions/deep-research` and `extensions/rerank`.
- **Removed extension directories: 0.** No manifest marks an extension deprecated. The only manifest changes are version bumps and new contracts (rerank, deep-research, clawrouter embedding/search, tencent hy4).
- **Feature commits (`feat`): about 17.** The rest are fixes, refactors, tests and UI work. The biggest churn is in memory-core (123 files), codex (115), telegram (84), browser (80), whatsapp (62), discord (60), knowledge (46), skill-workshop (46 added: moved out of core by 08f4a198a31).
- **Webhook signature or verification changes: none** in this window.
- **Inventory blind spots.** Some extensions existed before the baseline but are not mentioned in `docs/parity-agent/openclaw-inventory.md`: **knowledge** (38 tools), **memory-core standing intents**, bifrost, requesty, particle, liquid-ai, abliteration, admin-http-rpc, beam, oc-path. They are listed in a separate section below.

## Top 10 worth doing

| # | Feature | Why for SE Agent | SE Agent status | Effort |
|---|---|---|---|---|
| 1 | **Mask sensitive form-field values in browser snapshots** (password, one-time-code, cc-number, cc-csc) | Security. Autofilled secrets and OTPs reach the model context. | **missing**: `crates/seagent-browser/src/snapshot.rs:144-147` prints the AX `value` verbatim. `openclaw.rs:444` does too. Only values registered by the vault are redacted (`policy.rs:44`). | S |
| 2 | **SSRF/redirect guard on channel HTTP** (self-hosted channel APIs and inbound media downloads) | Security. Self-hosted Mattermost, Matrix, Nextcloud and ClickClack servers, and media URLs, can redirect to private or metadata hosts. | **missing**: `crates/seagent-channel/src/http.rs:34` uses an agent with ureq default redirects and no per-hop check. `get_bytes` (`http.rs:214`) is used for Discord attachments (`discord.rs:2076`). For comparison, seagent-media already vets each hop (`seagent-media/src/http.rs:262-279`). | M |
| 3 | **Bedrock: hide foundation models that can't be invoked on demand** | Fixes a real failure: discovered models fail with an on-demand-throughput error when selected. | **bug present**: `crates/seagent-model/src/bedrock.rs:386-447` lists every `modelSummaries` id with no `inferenceTypesSupported` filter. Inference profiles are not listed either. | S |
| 4 | **Rerank Decision provider** (any `/rerank` endpoint: vLLM, TEI, Infinity, Cohere, Jina, Voyage) | On-prem, cheap and model-agnostic. It also backs the recall gate (#5). | **missing**: `crates/seagent-kernel/src/decision.rs:7-9,489` only has `llm` and `openai` backends. | S-M |
| 5 | **Deep research tool** (bounded, quote-verified findings, explicit gaps, numeric ledger) | Ops research (CVE, vendor docs, incident background) with auditable citations. It uses plain `llm.complete` with no function calling, so it works with DeepSeek. | **missing**: no `deep_research` tool. The closest is the `share/skills/research/grounded-citations` skill. | M |
| 6 | **Decision-model recall gate** for memory (off/shadow/live, thresholds, 1.5 s budget, excerpts injected into the user turn) | Better recall precision. Shadow mode gives a safe rollout, which fits governance. | **partial**: `crates/seagent-memory/src/active.rs` (regex intent plus aux recall agent). It has no per-page scoring and no shadow mode. | M |
| 7 | **Skill Workshop autonomous modes** (`off`/`propose`/`auto`): LLM experience review, drafts queue (`/learn drafts`), per-review undo, skill-diet | `propose` (drafts that need approval) maps onto SE Agent's approval model. | **partial**: deterministic review in `crates/seagent-skills/src/core/review.rs`, stale/archive in `core/curator.rs` and `core/settings.rs:141-142`, rollback in `core/ledger.rs:170`, lint and authoring standard in `core/workshop.rs`. Missing: LLM review, propose/drafts mode, skill-diet. | M |
| 8 | **Knowledge vault** (pre-baseline, not in inventory): evidence-backed claims and relationships, per-store agent ACL, journaled writes with local Git history, supersede/withdraw/verify/merge, 38 `knowledge_*` tools | Runbook and CMDB-like knowledge with provenance and audit, scoped per agent. | **partial**: `crates/seagent-memory/src/wiki.rs` (claims with evidence and lint; 5 `wiki_*` tools). No store ACL, no Git history, no supersede chain. | L |
| 9 | **Ambient AWS credentials for Bedrock** (Mantle uses the core auth chain, IAM token) | EC2/EKS/on-prem deployments without static keys. | **partial**: Mantle is bearer-only (`crates/seagent-model/src/catalog.rs:154`). `sigv4.rs` `from_env` handles env, profile and `credential_process`, but not IMDS, ECS or web-identity. **Unverified** whether upstream reaches IMDS (the AWS SDK default chain does). | M |
| 10 | **Teams proactive DM to users who never messaged the bot** | Approval and on-call notifications to Teams approvers. | **partial / unverified**: `crates/seagent-channel/src/msteams.rs:16-17,301-303` creates the personal conversation, but needs a tenant and serviceUrl seen on an earlier inbound. | S-M |

Runners-up: standing intents, a `/fork` command that creates channel threads, the Gemini service tier (flex/priority), a Qoder ACP preset, and the Slack `list-pins` limit.

## Full table

| Feature | Upstream evidence | What it does | SE Agent status | Relevance | Effort |
|---|---|---|---|---|---|
| Rerank provider (new extension) | `extensions/rerank/{decision-provider,decision-codec}.ts`; 2ca7a3a0dee | Turns any `/rerank` endpoint into a Decision model. Retries with `documents` then `texts`; scores must be in [0,1]. | missing (`seagent-kernel/src/decision.rs` has `llm` and `openai` only) | high | S-M |
| Deep research (new extension) | `extensions/deep-research/src/{tool,evidence,validation}.ts`; README | Bounded multi-branch research: quote-integrity checks, support/contradiction audit, numeric ledger, explicit gaps, 60 KB corpus cap | missing | med-high | M |
| Knowledge recall gate | 2ca7a3a0dee; `extensions/knowledge/src/recall-gate.ts`, `recall-gate-hook.ts` | Per-turn decision-model scoring of candidate pages; off/shadow/live; injects ≤6000 chars into the user turn | partial: `seagent-memory/src/active.rs` (no scoring or shadow) | med | M |
| Knowledge keyword search through superseded wording | 4d153a7bce0; `extensions/knowledge/src/recall-keyword.ts` | BM25 keyword shortlist; follows `superseded_by` to the current record | missing (no supersede concept in `seagent-memory`) | low-med | S (once a vault exists) |
| Knowledge vault (pre-baseline, not inventoried) | `extensions/knowledge/` (223 src files, 38 tools, 9 bundled skills) | Evidence-backed pages, claims and relations; per-store `agents` ACL; journaled writes; Git history; chronicle/timeline | partial: `seagent-memory/src/wiki.rs` | med-high | L |
| Skill Workshop moved into a plugin, with autonomous modes | 08f4a198a31, 59373145f00; `extensions/skill-workshop/src/{experience-review*,drafts,review-undo,skill-diet,unused-archive}.ts` | Background LLM review saves or updates skills; `propose` keeps drafts; undo; 30-day unused archive; diet shrinks oversized skills | partial: `seagent-skills/src/core/{review,curator,ledger,workshop,lint}.rs`. Missing LLM review, propose/drafts, diet. | med | M |
| Gemini managed deep research | 8b023da72a1; `extensions/google/research*.ts` (Interactions API `deep-research-preview-04-2026`) | Start/poll/cancel Google-hosted deep research with citations | missing | low (vendor-locked) | M |
| Codex isolated completions via native runtime | 8d922199c07 | Codex app-server stdio worker for isolated completions | n/a (we have `seagent-model/src/codex_app.rs`; internal) | low | — |
| Thread `/fork` on Telegram, Discord and Slack | b515cc7f9f1, 69baaab4a95, 9066c989d58; `extensions/{telegram,discord}/src/conversation-fork.ts`, `extensions/slack/src/fork.ts` | `/fork [title]` copies the session and creates a sibling thread or topic with a literal recap | partial: session fork via CLI only (`crates/seagent/src/session_cli.rs:93`); no channel `/fork` | low-med | M |
| Plugin SDK: agent_end fork, hidden forked turn, command continuation with a replacement prompt, reauthorizing session work, starter prompts | 7d69dfc63c7, def63496ca8, d983e34a522, 1595dd24770, 071ea8338d9 | Plugin runtime capabilities (core-owned) | unverified (the core agent covers this) | low-med | — |
| Gemini fast mode / service tier | 6fa925242b8; `extensions/google/provider-policy.ts` | Maps fast mode to Gemini `service_tier` priority; also `flex`/`standard` | missing: `service_tier` only in `anthropic.rs:188`, `openai_chat.rs:112`, `responses.rs:91`, `codex_app.rs:218`; not in `gemini.rs` or `google.rs` | low-med (flex lowers cost) | S |
| Tencent hy4 on TokenHub and TokenPlan | 70aca1def5e | New model rows with a default thinking level | partial: providers exist (`seagent-model/src/catalog.rs:189-190`); `modelsdb.rs:422` has only `hy3` | low | S |
| ACP presets: Qoder (and Grok Build model selection) | 4d2706f4860, 89ec94869d9 | `qodercli` ACP agent; model selection in native chat | Grok Build preset present (`seagent-app/src/acp_client.rs:129`); **Qoder missing** | low | S |
| Bedrock: hide models without on-demand inference | 44ef0d6cc21 | Filters `inferenceTypesSupported` that lacks ON_DEMAND | **bug present** (`seagent-model/src/bedrock.rs:386-447`) | med-high | S |
| Bedrock: Grok 4.6 omit temperature / context window | de26bc55973, 05bfba3e453 | Model quirks | context window known (`modelsdb.rs:410`); temperature always sent (`bedrock.rs:120-126`), so the quirk is unverified for us | low | S |
| Bedrock Mantle with ambient AWS credentials | ef14d57860f | `auth: aws-sdk` gets an IAM token from ambient credentials | partial: bearer-only (`catalog.rs:154`); `sigv4.rs` lacks IMDS, ECS and web-identity | med-high | M |
| xAI: convert inline GIFs before Responses | 0a001864547 | xAI rejects GIF; converts it first | unverified / likely missing (no GIF conversion in `seagent-model`) | low | S |
| Anthropic: set API workspace at login | 807075d1d8f | Collects the workspace scope during API-key login | unverified (no `workspace` hit in `anthropic.rs` or `login.rs`) | low | S |
| ClawRouter catalog offers (embeddings, search, speech) | 5d9e391b232, 0a5f30f82d3, ab4bd268984, d65390bcf36 | OpenClaw's hosted router offers | n/a (vendor service) | low | — |
| Slack, Discord and Matrix `list-pins` honour `limit` | 413f0edb0c2 | Pin listing respects `limit` | **bug present on Slack** (`seagent-channel/src/slack_actions.rs:225-240` ignores limit); Discord and Matrix unverified | low | S |
| Teams proactive DM without a prior message | 24aff34974c | Creates a DM conversation for any user with the app installed | partial / unverified (`msteams.rs:16-17,301-303` needs a tenant from an earlier inbound) | med | S-M |
| Teams approval-card update in personal chats | 901ca49c612 | Edits the proactive approval card in the stored conversation | unverified (`msteams.rs` supports update via PUT) | med | S |
| Telegram fixes (rich text, typing, topics, polling cancel) | a8cfd72e342, c8ab75b50da, 9cb29007ed1, 3e3911e1d6d, 2ac42c830f3, 89596b4e6d4, 8953aa00e95 | Formatting and lifecycle fixes | unverified (per-case behaviour) | low | S each |
| WhatsApp LID retry / ambiguous lock recovery | b1170e68ffb, aec7f8bf9f9 | Retries DMs while LID identity is unavailable | unverified | low | S |
| Mattermost: posts with link previews dropped as system posts | c0f7a4d7b6c | Fixes system-post classification | unverified: check `seagent-channel/src/mattermost.rs` post-type filter | low-med | S |
| Memory robustness: retry after search timeout, dirty-index not blocking search, recover after embedding timeouts, same-host embedding server | 43d09522a4b, 5a22b8cd3e5, 0cbdb482bbb, 4ae6d6f057a | Indexing and search resilience | unverified for `seagent-memory/src/{index,embed}.rs` | med (on-prem local embeddings) | S-M |
| Standing intents (pre-baseline, not inventoried); this window adds conversation-scope and CJK fixes | `extensions/memory-core/src/standing-intents*.ts`; 405e63cb2a2, 3d76fcf775e | Keyword-triggered reminders scoped to sender, conversation or channel, with cooldown, max fires and expiry | missing (no hit in `crates/`) | low-med (e.g. change-freeze reminders) | M |
| Active-memory CJK, German and object-question triggers | b31b5212141, 366333d3252, 21940b9a8d5 | More languages trigger recall | partial: CJK handled (`active.rs:19`, `recall.rs:66`); German unverified | low | S |
| oc-path CLI (`oc://` workspace addressing), redaction-sentinel guard | ab4074fb57e, 5b186a1636e | Path-addressed edits; refuses to write `__OPENCLAW_REDACTED__` markers | missing (whole extension); the sentinel concept may apply to our config editing (unverified) | low | S (guard only) |
| Bifrost, Requesty, Particle, Liquid AI (decision), Abliteration providers (pre-baseline, not inventoried) | `extensions/{bifrost,requesty,particle,liquid-ai,abliteration}` | Model routers and providers | missing as presets; usable through a generic OpenAI-compatible endpoint (LiteLLM preset at `catalog.rs:119`). Bifrost (self-hostable gateway) is the most relevant. | low-med | S each |
| Admin HTTP RPC (pre-baseline) | `extensions/admin-http-rpc` | `POST /api/v1/admin/rpc` with a method allowlist | have: `POST /arp` JSON-RPC (`seagent-app/src/server.rs:343`) | — | — |
| Beam (session snapshot sharing) | 7552558bfb3, ec7b5641053 | Share session snapshots; restricted guests | partial: `seagent-app/src/session_share.rs` | low | — |

## Security fixes in extensions we ported

| Upstream fix | Applies to SE Agent? | Evidence on our side |
|---|---|---|
| da41e7de258 browser: mask password, OTP and card values in snapshots | **Yes, gap** | `seagent-browser/src/snapshot.rs:144-147`, `openclaw.rs:444` print `value` raw |
| 0e7aab7cd5c browser: refuse strict-mode navigation when redirect hops can't be inspected | **Partial** | We only check after the fact (`seagent-browser/src/policy.rs:185 check_final_url`), so a redirect hop has already reached the private host. `Fetch.enable` is used only for the bridge host (`engine.rs:544`). Upstream fences each hop (`pw-session-navigation-fence.ts`, pre-baseline). |
| 36207738b52 browser: tab close exempt from URL policy | Probably fine; unverified | — |
| 97e996675b4 clickclack: block redirects to unrelated private services | **Yes, gap** | `seagent-channel/src/http.rs:34` agent follows redirects and has no SSRF check. This applies to every self-hosted channel. |
| 70c99be459a discord: CDN downloads must not inherit private-network access | **Partial** (we have no guard at all) | `discord.rs:2076` → `http::get_bytes` (`http.rs:214`) |
| ee8f4da1d7e feishu: refuse card actions when the chat type is unknown | Review | `seagent-channel/src/feishu.rs:927` defaults an unknown chat to `Group` instead of refusing |
| bde2d30676c msteams: allowlists lost after an unrelated config reload | Unverified (TS-specific caching) | — |
| 5389c2a105c matrix: forget cached credentials when an account is removed | Probably n/a (no cached Matrix credentials found in `matrix.rs`) | — |
| 2099259f3f4 X: bound oversized API and media responses | Have | `http.rs:10` `MAX_BODY` 16 MB; `get_bytes` takes `max` |
| 967dd72c07f ollama: embeddings and private-network policy | n/a: our embeddings have no SSRF policy (a hardening gap, low) | `seagent-memory/src/embed.rs` |
| ab4074fb57e / 5b186a1636e oc-path: refuse writing redaction sentinels | Unverified: check whether any config/secret editor can write `[REDACTED]` placeholders back | — |
| 9701d0ffeb1 xAI OAuth stale expiry; e72b356459b Anthropic token-profile collisions; 4845a0f9a71 refuse removed CLI accounts | Unverified | — |

No webhook signature or verification changes landed in this window.

## Removed or deprecated extensions we copied

None. No extension directory was removed, and no manifest adds a deprecation. 08f4a198a31 moved Skill Workshop from core into `extensions/skill-workshop` (and 1ba543b6dd6 stopped naming it in `/learn` prompts). That is a relocation; the `skill_workshop` tool contract is unchanged.

## Stale ⬜ rows in our inventory (implemented in our code)

- workboard ⬜ → `crates/seagent-kernel/src/kanban/` (OpenClaw `workboard_*` vocabulary)
- logbook ⬜ → `crates/seagent-app/src/logbook.rs`
- skill_workshop 🚧 → mostly there (`seagent-skills/src/core/{workshop,lint,review,curator,ledger}.rs`)
- memory-wiki ⬜ → `crates/seagent-memory/src/wiki.rs`
- active-memory ⬜ → `crates/seagent-memory/src/active.rs`
- session-share → `crates/seagent-app/src/session_share.rs`
