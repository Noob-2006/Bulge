# OpenClaw core changes since 4e4342b9 that SE Agent lacks

Upstream range: `4e4342b9..8a186ad7ad7` (2026-11-01 → 2026-11-06), excluding `extensions/`.
That is 2,160 commits: 1,257 fix, 276 improve, 204 test, 109 refactor, 96 perf, 87 feat, 83 chore, 37 docs and 11 ci.
About 40% are CI, test, iOS or macOS, release, i18n or UI-copy churn. 41 commits are `feat(openclaw-id|beam|ios|clawrouter|…)`, which are consumer identity, mesh or mobile work, so they're out of scope.
Method: I grouped the feat, improve and fix subjects, read the diffs of the candidates, and grepped `crates/`, `ui/web`, `share/` and `docs/` in SEAgent before marking anything missing.
I read the code; I didn't run anything. "unverified" means I didn't confirm it by tracing the code.

## Top 10 worth doing

| # | Item | Why | Effort |
|---|---|---|---|
| 1 | **SECURITY: safe-builtin `test`/`[` exemption runs command substitution**. Port 3f7ee388a1f plus the earlier `-v` guard. | `crates/seagent-security/src/approvals.rs:740` puts `test` and `[` on the closed safe list with no operand checks, and `exec_allowlisted` (approvals.rs:826) returns early for them. `shell::lex` (`crates/seagent-kernel/src/shell.rs:195`) doesn't look inside single quotes, so `test -v 'a[$(cmd)]'` parses as a harmless `test`, but bash ≥4.2 runs `cmd` anyway. Upstream already guarded `-v` before the baseline. The new commit also refuses `$'…'` (ANSI-C) and glob or expansion characters in predicate operands. This affects `security = allowlist` in secgate.rs:560 and 1262. I didn't run it, so I can't say whether another gate catches it; a unit test will settle that. | S |
| 2 | **Per-model or per-provider exec ceiling** (990fc1bd88b) | You can put one model (a cheap, external or untrusted provider) behind stricter exec security or ask without changing the others. The stricter setting always wins, including over `/elevated` and yolo. Our `tool_policy.by_provider` (toolpolicy.rs:134) can only allow or deny a whole tool, and `effective_exec` (approvals.rs:574) ignores the model. | S |
| 3 | **Explain why a tool is or isn't available** (baaf869a3a4, `src/agents/tool-availability-explanation.ts`) | It replays the real policy pipeline and reports the blocking stage (deny, profile, provider, sandbox, model, harness) plus the config fix. Operators need this to debug layered policy (global, by_provider, by_channel, by_sender, role, sandbox). We have nothing like it; `seagent tools` only lists and toggles. | S–M |
| 4 | **Cron default delivery and failure-alert destinations, gateway-wide, per agent and per creator** (87c9eb3fc54, 57405d6f170, eeab083a5bd) | Failure alerts from route-less jobs go to an on-call channel without editing every job. We only have per-job `deliver` and `failure_deliver` (`cronjob/mod.rs:67-70`); `[automation]` has no default. | S |
| 5 | **Console: standing grants and exec policy per host and agent** (new `ui/src/pages/approvals/standing-grant-row.tsx`, `approval-history-row.tsx`; 554115b788f) | Approvers need to see and revoke standing grants where they approve. We have the CLI (`security_cli.rs:194/224` list and revoke) but the console Approvals page (`ui/web/ops.js:255`) only shows pending items and recent audit rows. | M |
| 6 | **Console security posture page** (0a93e420f4f, `ui/src/pages/config/security*.tsx`) | One page showing what is exposed (listeners, tokens, tunnels) and what agents can do (exec security, ask, sandbox, elevated). Unknown host policy shows as "unknown", never as safe. We have it piecemeal in the CLI (exposure, `security_cli` exec show); there is no console view. | M |
| 7 | **Node-hosted MCP tools, with questions forwarded through the gateway** (e7f19b1192d, e0ac3370bbe, b3487e66de8; `src/worker/worker-local-mcp.ts`, `src/gateway/node-mcp-policy.ts`) | MCP servers run on the managed host (DB, k8s or vendor CLIs that must run on-box). The gateway applies policy and relays elicitation to the operator. We have the partial: `node.toml [plugins]` exposes `node_commands` only (`crates/seagent-app/src/node.rs:1031,1596`), not MCP tools as agent tools, and there's no elicitation relay. | L |
| 8 | **Operator `tools.invoke` RPC/HTTP that also runs configured MCP tools under policy** (7ffee4a438d, `src/gateway/tools-invoke-mcp.ts`) | Scripts or runbooks can call one tool directly through the same gate, audit and policy, with no model turn. We have no `tools.invoke` ARP method; `daemon.rs:659` has only `tools.list`. `seagent call` (main.rs:2360) works only from inside coderun. | M |
| 9 | **Attribute and hook user stops** (71e516af03a `run_stopped` hook) | We want "who stopped which run" in the audit trail. `Kernel::interrupt` (kernel.rs:589) just cancels. `session.interrupt` (daemon.rs:609) records no actor, writes no audit event and fires no hook. | S |
| 10 | **Expire disposable agent scratch and idle worktrees** (99ba844a3cd, `src/infra/scratch-expiry.ts`, `scratch-cleanup.ts`; existing 7-day idle worktree GC) | Disk hygiene on long-lived on-prem daemons: bounded, no symlink following, live runs protected. We only have `worktree::prune` (worktree.rs:188) on demand, with no age-based scratch or worktree expiry. | S–M |

## Feature gaps (core, non-extension)

| Feature | Upstream evidence | What it does | SE Agent status | Relevance | Effort |
|---|---|---|---|---|---|
| Exec mode ceiling per provider or model | 990fc1bd88b; `src/agents/session-permission-exec-mode.ts`, `agent-tools.execution-policy.ts`, `tools.byProvider[...].exec.mode` | Restrict-only exec security and ask cap for turns on a given model | **partial**: `crates/seagent-security/src/toolpolicy.rs:134` (tool allow/deny per provider only) | high | S |
| Tool availability explanation | baaf869a3a4; `src/agents/tool-availability-explanation.ts`, `tool-availability-session-gates.runtime.ts` | Says why tool X is blocked (stage plus fix), for doctor and the API | **missing**: `crates/seagent/src/ops/toolcfg.rs` lists and toggles only | high | S–M |
| Cron default delivery and failure destinations | 87c9eb3fc54 (`cron.delivery`, `cron.agents.<id>.{delivery,failureAlert}`, `cron.creators.<profile>`), 57405d6f170, eeab083a5bd | Gateway, agent and creator defaults, resolved at run time | **partial**: per-job only, `crates/seagent-kernel/src/cronjob/mod.rs:67-70` | high | S |
| Cron: stopped turns raise failure alerts | f517164d87e | An operator-stopped cron turn counts as a failure for alerting | unverified (`automation.rs` run_job) | med | S |
| Approvals console: standing grants and history | `ui/src/pages/approvals/standing-grant-row.tsx`, `approval-history-row.tsx`, fb70290714a, 9c5f014050e | List and revoke standing grants; readable history | **partial**: CLI `crates/seagent/src/security_cli.rs:194,224`; console `ui/web/ops.js:255` pending and audit only | med-high | M |
| Exec policy per host and agent, edited in place | 554115b788f; `ui/src/pages/devices/devices-policy-actions.ts` | View and edit exec approvals per node and agent from the UI | **partial**: CLI `security_cli.rs:398-445` (global); roles give per-agent presets (`crates/seagent-kernel/src/roles.rs:312`) | med | M |
| Security posture page | 0a93e420f4f; `ui/src/pages/config/security-model.ts` | Exposure plus what agents can do, with stale facts invalidated | **partial**: CLI only (exposure, `security_cli`) | med | M |
| Attended-session permission defaults | 65a125adc59; `src/gateway/session-create-existing-selection.ts`, `agents.list[].permissionMode` default | Per-agent default mode for newly attended sessions; `full` needs live admin | **partial**: role `Policy.approval` tightens (`roles.rs:312`); no per-agent default mode for new sessions | med | S |
| Node-hosted MCP tools and elicitation relay | e7f19b1192d, e0ac3370bbe, b3487e66de8; `src/worker/worker-local-mcp.ts`, `src/gateway/node-mcp-elicitation.ts`, `node-mcp-policy.ts` | Runs MCP on the node that hosts it; questions go to the operator through the gateway | **partial**: `node.rs:1031` node plugins expose `node_commands` only | med-high | L |
| `tools.invoke` (RPC/HTTP), including MCP tools | 7ffee4a438d; `src/gateway/tools-invoke-mcp.ts` | Direct, policy-gated tool call without a model turn | **missing**: `crates/seagent-kernel/src/daemon.rs:659` has `tools.list` only; `seagent call` is coderun-only | med | M |
| `run_stopped` hook and stop attribution | 71e516af03a | Hook and record for user-confirmed stops | **partial**: `kernel.rs:589`, `daemon.rs:609` cancel with no audit or hook | med | S |
| Scratch expiry (24 h) and idle worktree GC | 99ba844a3cd; `src/infra/scratch-expiry.ts`, `src/gateway/scratch-maintenance-custody.ts`; 0afeaad457c (worktrees remain after merge) | Bounded periodic cleanup of agent tmp and worktrees | **partial**: `crates/seagent-kernel/src/worktree.rs:188` manual prune | med | S–M |
| "Send now" for pending steers (interrupt the current tool call, keep the run) | a956ef17145; `src/gateway/server-methods/chat-steer-now-handler.ts` | Aborts the in-flight tool call through a per-call signal; the steer is delivered at once | **partial**: steering waits for the next tool boundary (`crates/seagent-kernel/src/queue.rs:4`); `session.interrupt` stops the whole run | low-med | M |
| Host disk paths only for admin-scope `system.info` | 9341d60e90b; `src/gateway/server-methods/system.ts` | Read-only callers get sizes but no host paths | **unverified**: `read`-scope tokens exist (`crates/seagent-app/src/exposure.rs:13`); I didn't check whether any read-allowed ARP method returns host paths | med | S |
| One session can't stall shared server I/O | ad1a025f8ac | Bounded hydration and metadata reads per session | unverified (different storage design) | low | — |
| Prometheus: SQLite reader counters | 6deb24aa465 | Cumulative read ops and bytes metrics | **partial**: `/metrics` exists (`crates/seagent-app/src/metrics.rs`) | low | S |
| API key verified on save | 67d0e1c3c79 | Live probe after saving a key | **have**: `crates/seagent/src/setup.rs:539` (setup); console unverified | low | S |
| Read-only PostgreSQL standby inspection | cf50d4a3662 | Inspect state from a read-only replica | **have (different design)**: HA standby serves reads only (`daemon.rs:750 standby_may_serve`); no PostgreSQL store | low | — |
| Session fork from the UI composer, nested empty sessions | 06c1a59bc20, 55911d9a78c, b515cc7f9f1 | Fork or branch conversations in the UI | **partial**: CLI `seagent session fork` (`crates/seagent/src/session_cli.rs`); not in the console | low | S |
| Plugin SDK additions: hidden forked turn, background notices, command continuation, starter prompts, skill-usage and authoring runtime, `agent_end` with turn | def63496ca8, 2163664150d, d983e34a522, 071ea8338d9, 53066f2a5a4, 09f0b0b4008, 59373145f00, 7d69dfc63c7, 43bb559f841, 1595dd24770 | Extension API surface | **missing** (hooks we have: `agent_end`, `before/after_tool_call`, `session_*`, `message_received`, `llm_output`) | low | M each |
| Provider names and artwork, template preview, sidebar auto-load, dismissable read-only banner, Team header | 5fe46054f10, 2d54096e462, 87e94821a87, ae4828f528a, 9edb1d3e633 | UI polish | missing | low | S |
| Chat input custody capability advertisement | 323df2111e8 | Handshake advertises queue mode and receipt shape | missing (ARP `initialize`) | low | S |
| Backup: exclude worktree templates | d9627ecb437 | Backup option | N/A (no templates; `crates/seagent/src/ops/backup.rs` has `exclude-secrets` and `no-sessions`) | low | — |
| DB recovery of retained workspace and skill dependencies; disk-authoritative repository workspaces; PostgreSQL namespace prep | 8129b061ba0, 68a413a67ab, 8085604eb96, cbb3bc5463c | Cloud-worker state recovery | N/A (no cloud-worker or PostgreSQL state) | low | — |
| Knowledge recall gate; superseded-record keyword search | 2ca7a3a0dee, 4d153a7bce0 (mostly `extensions/knowledge`) | Model-scored recall injection; supersede-chain search | deferred to the extensions agent; no supersede concept in `seagent-memory` | med | M |

## Upstream security fixes that may apply to code we ported

| Fix | Upstream | Applies to SE Agent? | Action |
|---|---|---|---|
| Dynamic shell predicates need approval (`test -v 'a[$(x)]'`, `$'…'` with globs) | 3f7ee388a1f; `src/infra/exec-safe-builtins.ts`, `exec-authorization-render.ts` | **YES, likely vulnerable.** `approvals.rs:740` `SAFE_BUILTINS` includes `test` and `[` with no operand check (we missed even the pre-baseline `-v` guard). `shell.rs` lex has no ANSI-C `$'` handling. | Allow `test`/`[` only when the raw source has no `\ $ \` * ? { } [ ]` and no `-v`. Add regression tests. I haven't confirmed this with a test (other gates may still catch some payloads). |
| Installer keeps the runtime private under umask 0002 | eb5d0cb5ea5 (`scripts/install.sh`) | **partial.** `packaging/install.sh:310` uses `cp -R` for the share dir (skills, roles, blueprints) with the caller's umask. The binary is `install -m 0755`. | Add `umask 022` (strip group and world write) in install.sh and install-offline.sh. |
| Host disk paths hidden from read-only callers | 9341d60e90b | **unverified**: we have `read`-scope tokens | Audit which methods `read` scope may call and what paths they return. |
| Registry downloads guarded against private redirects | f2084811c1d | **have**: `crates/seagent-skills/src/hub/http.rs:2-3,177` checks every hop by hand. The update download is signature-verified (`ops/update.rs`). | none |
| `config set` audit redaction with interspersed options | c5c37ca1b95 | **N/A**: `crates/seagent/src/ops/confcli.rs:348` audits only the key, never the value | none |
| Reserved keys (`__proto__`) in KEY=VALUE provider and MCP env | 0468e735508 | N/A (Rust maps) | none |
| Non-regular (FIFO) recovery manifests and native-hook credentials read before stat | a90f3e24c20, 2dd3ffec006 | **mostly have**: `crates/seagent-security/src/credfiles.rs:40` checks `is_file()` after realpath. Other secret-file readers (secrets.toml, key files) are unverified. | Low-priority sweep for `read_to_string` on operator-supplied paths. |
| Credential symlink to a path under a regular file (ENOTDIR) | 92eb7710aa1 | N/A or low | none |
| Media CLI `..` through symlinked parents | 01d39248e97 | **have**: `crates/seagent-security/src/paths.rs:46` `realpath` canonicalizes through the OS before normalizing | none |
| Workspace `.env` must not add PATH bootstrap roots (MISE_DATA_DIR, XDG_BIN_HOME) | 076924b41ef | N/A: we don't load workspace `.env` into the child env (`paths.rs:38` treats them as protected) | none |
| Egress proxy: pin CONNECT tunnels to loopback origins | 6769a693191 | **likely N/A**: `egress_proxy.rs` dials the vetted address and never injects into CONNECT. Node-fetch-to-loopback dev hosts unverified. | Optional test: CONNECT to an allowed dev host with a different inner Host. |
| Web search honors sandbox provider trust | 3e3935a6b4a | N/A (no workspace or external search-provider plugins) | none |
| Empty plugin default entries widen `plugins.allow` | 2cd45a3eaff | N/A (unverified; no auto-enable materialization) | none |
| Strict Chrome-MCP navigation without redirect inspection | 0e7aab7cd5c (`extensions/browser`) | deferred to the extensions agent | — |
| Guest privacy: person activity timelines, login emails in shared labels, Actions widgets limited to approved queries | 5d3e157432a, 1248bee4959, d0e78b07144 | unverified for `crates/seagent-app/src/session_share.rs` and multi-user console | Low-priority review. |

I checked these robustness fixes and found nothing to port: the cron budget uses `Instant` (`automation.rs:223`, `cronjob/script.rs:123`), and an exec whose daemonized grandchild keeps the pipe open is handled (`seagent-tools/src/shell.rs:357`).

## Removed or deprecated upstream: did we copy any of it?

| Upstream removal | Commit | In SE Agent? |
|---|---|---|
| `skill_workshop` split, with personal authoring moved to the new `skill_library` tool | 3c8129e3d47 | not ported (0 hits) |
| Legacy template manifest formats (`openclaw.claw`, JSON manifests) | f8dfafe4470 | not ported |
| Plugin prompt-permission config renamed ("modification") with a Doctor migration | 13374fde99e | not ported |
| `HEARTBEAT_RESPONSE_TOOL_NAME` plugin-SDK export removed | d5e35ca8321 (#180106) | not applicable |
| Retired npm channel retries, catalog lookup forwards, i18n glossary enforcement | 28a93a00ac7, 645c18850ba, 06d4059a3d0 | not applicable |

None of our code depends on anything upstream removed in this range.

## Counts

- Feature rows: 25. Of these, 2 are missing and high or med-high, 15 are partial, 2 are have or have (different design), 3 are N/A or deferred and 3 are low-value missing. 3 of the 25 are unverified (one of them is also partial).
- Security rows: 15. 1 likely applies (high), 1 partially applies, 1 likely N/A, 3 have, 6 N/A and 3 unverified or deferred.
- Top 10: 1 security fix, 9 features (all S–M except node-hosted MCP, which is L).
