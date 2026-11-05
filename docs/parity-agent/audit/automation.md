# 稽核：automation 串流

- 串流：automation（cron／心跳／Kanban／看板與工作面／message 工具／平台工具／投票／外送 webhook／流程／hooks）
- 目錄：`$R/w-automation`（基底 commit 5c369e5，未提交）
- 編譯/測試：**無法編譯**。`seagent-kernel` lib 53 個錯誤、lib test 79 個錯誤，所以整個 workspace 沒有任何測試能跑（通過 0／失敗 0）。主要錯誤：`HookEvent` 缺 `AgentTurnPrepare`、`BeforePromptBuild`、`BeforeModelResolve`、`BeforeMessageWrite`、`BeforeAgentRun`、`BeforeAgentReply`、`SubagentProgress`、`InboundClaim`、`BeforeReset`、`CronReconciled`、`SkillChanged` 等變體（E0599/E0408）；`config.kanban` 是 `toml::Table`，但 kanban/dispatch.rs、methods.rs 當成 `&KanbanConfig` 用（E0308 ×14，E0609 `diagnostics`/`enabled`/`dispatch`/`failure_limit`）。seagent-kernel 之後的 crate 沒有編到，所以 main.rs 缺的 mod 宣告還沒報錯，但修完 kernel 後預期也會失敗。原始輸出：`audit/automation-tests.txt`。
- 差異範圍：修改 27 個追蹤檔（+798/−47 行）；新增 49 個未追蹤原始碼檔（共約 24,666 行），另有 `docs/parity-agent/{hermes,openclaw}-inventory.md` 兩份盤點副本。**沒有** `docs/parity-agent/automation.md`（串流文件未寫）。
  - 新增主要區塊：`crates/seagent-kernel/src/kanban/`（23 檔）、`crates/seagent-app/src/surfaces/`（11 檔）＋`ui/web/surfaces.js`、`crates/seagent-channel/src/{action_args,discord_actions,discord_tools,slack_actions,telegram_actions}.rs`、`crates/seagent/src/{hooks_ext,hooks_bundled,hooks_cli,hooks_outbound,gmail_hook,outbound_host}.rs`、`crates/seagent-kernel/src/{outbound,wake}.rs`、`crates/seagent-kernel/src/kernel/hookpoints.rs`。
- 狀態統計（共 112 列）：✅ 17　🚧 60　⬜ 34　N/A 1

## ⚠ 合併損壞（影響幾乎所有新程式碼的判定）

w-automation 是 4 個平行 worktree（parked/wt-hooks、wt-kanban、wt-platform、wt-surfaces）**合併沒合好**的結果。以下每一項都會讓 workspace 無法編譯（依程式碼判讀，未實際建置）：

1. **`crates/seagent-kernel/src/hooks.rs` 少了 19 個 `HookEvent` 變體**（`ALL` 只有 32 個，wt-hooks 版本有 51 個）。`kernel.rs`、`kernel/hookpoints.rs`、`tests/runner.rs`、`crates/seagent/src/hooks_*.rs`，以及 hooks.rs 自己的測試 `openclaw_hook_points_have_their_own_events`，都用到 `BeforeModelResolve`、`AgentTurnPrepare`、`BeforePromptBuild`、`BeforeAgentReply`、`BeforeAgentRun`、`BeforeAgentFinalize`、`InboundClaim`、`BeforeDispatch`、`ReplyDispatch`、`SubagentProgress`、`SubagentDeliveryTarget`、`CronReconciled`、`SkillChanged`、`BeforeInstall`、`ResolveExecEnv`、`ChannelPairingRequested`、`BeforeMessageWrite`、`BeforeReset`、`Command`。結果是 **seagent-kernel 編譯失敗**，連帶 seagent-app 與 SE Agent 也無法編譯。
2. **`crates/seagent/src/main.rs` 沒有宣告 `mod gmail_hook; mod hooks_bundled; mod hooks_cli; mod hooks_ext; mod hooks_outbound;`**（wt-hooks 版本有）。但 `main.rs`（`hooks_cli::cmd`、`hooks_ext::start_daemon_services`、`hooks_ext::now_iso`、`cmd_webhook test`）和 `ext.rs`（`crate::hooks_ext::load/inbound_claim/before_dispatch/reply_dispatch/auto_reset/pairing_requested/command_event`）都在呼叫它們，所以 SE Agent 二進位無法編譯。另外，`ext.rs` 原本的 `hooks::shell_hooks(&cfg.hooks)` 已被換成 `crate::hooks_ext::load`，**既有的 shell hooks 功能因此一併壞掉**。
3. **`config.rs` 的 `kanban` 欄位型別不對**：w 版是 `toml::Table`，但 `kanban/methods.rs:39`、`dispatch.rs:912`、`testutil` 都把 `k.cfg.kanban` 當成 `KanbanConfig` 使用（wt-kanban 版宣告的是 `pub kanban: crate::kanban::KanbanConfig`）。
4. **`config.rs` 沒有 `surfaces` 欄位**：`surfaces/mod.rs:84` 用到 `cfg.surfaces`（wt-surfaces 版有 `pub surfaces: toml::Table`）。
5. **安全退步**：w 的 `PROJECT_GATED` 沒有 `hooks_extra`（wt-hooks 版有）。一旦 hooks_ext 接上線，不受信任的專案設定就能用 `[hooks_extra] auto_accept = true` 繞過「首次使用同意」，或啟用 gmail／outbound。反過來，w 把 `webhooks`、`kanban`、`meetings`、`workflows`、`integrations` 加進了 gate。
6. w 的 config.rs 另外新增了 8 個沒人使用的 `toml::Table` 欄位（`automation`、`heartbeat`、`webhooks`、`canvas`、`meetings`、`workflows`、`integrations`，以及型別錯誤的 `kanban`），看起來像主審留下的骨架，沒有任何程式讀取它們。

判定規則：如果新程式碼本身的接線或型別直接被上述問題打斷，判 🚧，並在證據欄寫「parked 可補」。既有、未改動的 ✅ 列維持 ✅，標「既有，未改動」，但它們同樣受全域編譯失敗影響。

---

## Hermes

### H§1（cron／訊息相關列）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| cronjob_manage（模型可用排程工具） | tools/cronjob_tools.py（H§1） | ⬜ | 整個 workspace 都沒有 cron／automations 工具。`automation.rs` 未改動；`wake.rs` 的註解提到 "the `automations` tool"，但這個工具不存在。parked：無 |
| send_message（函式庫） | tools/send_message_tool.py（H§1） | ✅ | 既有，未改動：`seagent-channel/src/tool.rs` `channel_send` ＋ `seagent channel send` |

### H§3 平台綁定／外掛工具

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| discord | tools/discord_tool.py（H§3） | ✅ | `seagent-channel/src/discord_tools.rs`：`tools()` 依 intents 動態產生 schema（search_members／fetch_messages／create_thread），經 `Channel::tools()` 接到 `crates/seagent/src/ext.rs:152`。測試 `core_tool_actions_and_schema`、`intents_from_app_flags_and_allowlist`。⚠ SE Agent 二進位目前因合併損壞無法編譯。parked/wt-platform、wtp-discord：與 w 相同 |
| discord_admin | tools/discord_tool.py（H§3） | ✅ | 同檔：12 個 admin 動作、403 指引、`server_actions` 白名單（discord.rs Config）。測試 `admin_tool_actions_and_403_guidance`。⚠ 同上 |
| feishu_doc_read | tools/feishu_doc_tool.py（H§3） | ⬜ | 沒有 feishu 工具。parked/wtp-feishu、wtp-feishu2 只有 `action_args.rs`＋lib.rs trait 擴充（與 w 相同），飛書工具的實作根本沒開始 |
| feishu_drive_list_comments | tools/feishu_drive_tool.py（H§3） | 🚧 | 既有，未改動：feishu/comment.rs 把留言注入提示，不是工具 |
| feishu_drive_list_comment_replies | 同上（H§3） | 🚧 | 既有，未改動：同上 |
| feishu_drive_reply_comment | 同上（H§3） | 🚧 | 既有，未改動：channel 回覆會進 thread，不是工具 |
| feishu_drive_add_comment | 同上（H§3） | 🚧 | 既有，未改動：comment.rs 有 1069302 fallback，不是工具 |
| yb_query_group_info | tools/yuanbao_tools.py（H§3） | ⬜ | yuanbao.rs 未改動，沒有 `tools()` |
| yb_query_group_members | 同上（H§3） | ⬜ | — |
| yb_send_dm | 同上（H§3） | ⬜ | — |
| yb_search_sticker | 同上（H§3） | ⬜ | — |
| yb_send_sticker | 同上（H§3） | ⬜ | — |
| meet_join | plugins/google_meet/tools.py（H§3） | ⬜ | 只有 config.rs 的 `meetings: toml::Table` 骨架，沒有程式 |
| meet_status | 同上（H§3） | ⬜ | — |
| meet_transcript | 同上（H§3） | ⬜ | — |
| meet_leave | 同上（H§3） | ⬜ | — |
| meet_say | 同上（H§3） | ⬜ | — |
| Teams 會議管線 | plugins/teams_pipeline（H§3） | ⬜ | — |
| context_engine 執行期工具 | agent/context_engine.py（H§3） | 🚧 | 既有，未改動：engine.rs 沒有讓 engine 帶自己的工具 |

### H§5 Kanban

共通狀況：`seagent-kernel/src/kanban/` 已用 `pub mod kanban` 宣告（lib.rs）。15 個 `kanban_*` 工具在 `kanban/tools.rs`（`NAMES`、`schema()`、`KanbanTool::run`），只透過派工器接線：`dispatch.rs:294` 對 worker session 呼叫 `set_session_tools(worker_tools)`。`orchestrator_tools()`（含 kanban_list／kanban_unblock）**除了 testutil 以外沒有任何呼叫者**，`KanbanConfig.enabled` 文件說的「offer to every session」並沒有實作。**`kanban/tools/tests.rs`、`dispatch/tests.rs`、`llm/tests.rs`、`workboard/tests.rs` 都只有一行 `use super::*;`，沒有任何測試**。`ops/tests.rs` 有 8 個測試涵蓋核心狀態機（create／link／claim／complete／block／review／attach…）。另外 `cfg.kanban` 型別錯誤（見合併損壞第 3 點）。parked/wt-kanban 的 kanban/ 全部與 w 相同，只差 config.rs 型別正確；即使合併成功，工具層仍然沒有測試、orchestrator 工具仍未接線，所以**合併後仍是 🚧**。

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| kanban_show | tools/kanban_tools.py（H§5） | 🚧 | tools.rs `"kanban_show"`，底層 `context::build_worker_context`（context.rs 有 1 個測試）。工具層無測試；cfg 型別錯誤 |
| kanban_list | 同上（H§5） | 🚧 | tools.rs：屬於 orchestrator-only，但 `orchestrator_tools()` 從未註冊給任何 session，模型實際拿不到 |
| kanban_create | 同上（H§5） | 🚧 | tools.rs → `ops::create_task`（測試 `create_gating_idempotency_and_validation`）。工具層無測試 |
| kanban_complete | 同上（H§5） | 🚧 | tools.rs `complete_task`：phantom card 檢查、artifacts、PR 驗收、judge。ops 測試 `claim_complete_handoff_and_gates`；工具層無測試 |
| kanban_block / kanban_unblock | 同上（H§5） | 🚧 | ops 測試 `block_kinds_loop_detection_and_unblock`；kanban_unblock 是 orchestrator-only，未註冊 |
| kanban_request_review / kanban_request_changes | 同上（H§5） | 🚧 | ops 測試 `review_cycle_routes_back_to_implementer`；工具層無測試 |
| kanban_heartbeat | 同上（H§5） | 🚧 | tools.rs `"kanban_heartbeat"`；無測試 |
| kanban_comment | 同上（H§5） | 🚧 | tools.rs；無工具層測試 |
| kanban_link | 同上（H§5） | 🚧 | ops 測試 `link_cycles_and_running_children`；工具層無測試 |
| kanban_attach / kanban_attach_url / kanban_attachments | 同上（H§5） | 🚧 | ops 測試 `attachments_names_caps_and_redaction`；`download_capped`（attach_url）無測試 |
| kanban_schedule | tools/kanban_tools_schemas.py（H§5） | 🚧 | tools.rs ＋ `ops::schedule`（block 測試有涵蓋）；工具層無測試 |
| Kanban 派工器 | hermes_cli/kanban_db_dispatch.py, kanban_worker_client.py（H§5） | 🚧 | dispatch.rs `daemon_tick` 已接到 daemon.rs:212，`KernelSpawner`、`tick_board` 都有，`RecordingSpawner` 也寫好了，但 **dispatch/tests.rs 是空的**；cfg 型別錯誤；沒有 `seagent kanban daemon` CLI（config 文件卻提到它） |
| kanban decompose / specify | hermes_cli/kanban_decompose.py, kanban_specify.py（H§5） | 🚧 | llm.rs `specify_task`/`decompose_task`，只能經 ARP `kanban.specify`/`kanban.decompose`（methods.rs）與 auto_decompose 觸發；**llm/tests.rs 空**；沒有 CLI／slash |
| kanban swarm / workflow 欄位 | hermes_cli/kanban_swarm.py, kanban_workflow.py（H§5） | 🚧 | workflow.rs 有接線（methods `kanban.workflow`、ops），1 個測試；**swarm.rs 沒有任何呼叫者（未接線）**，只有 1 個單元測試 |
| kanban PR acceptance | hermes_cli/kanban_pr_acceptance*.py（H§5） | 🚧 | pr.rs（GitHub head 驗收）由 ops/tools complete 呼叫，3 個測試（fake GH）；受 cfg 型別錯誤阻擋；工具路徑無測試 |
| kanban 多看板／轉移／診斷 | hermes_cli/kanban_boards.py, kanban_transfer.py, kanban_diagnostics.py（H§5） | 🚧 | boards.rs、diagnostics.rs 經 ARP（`kanban.boards`/`board_create`/`board_remove`/`diagnostics`）接線，各有 1 個測試；**transfer.rs（export/import tar）沒有呼叫者，也沒有 CLI** |
| kanban 儀表板 / systemd | plugins/kanban/dashboard, plugins/kanban/systemd（H§5） | 🚧 | 只有 ARP 方法 `kanban.*`（methods.rs，22 個），**ui/web 沒有 kanban 頁面**（surfaces.js 只有 session board）；systemd 由 seagentd 服務涵蓋，沒有獨立單元 |

### H§14 排程與自動化

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| cron 排程器 | cron/scheduler*.py, jobs.py（H§14） | ✅ | 既有，未改動：seagent-kernel/cron.rs、automation.rs、daemon 排程 |
| cron 投遞到平台（deliver/failure_deliver） | cron/scheduler_delivery.py（H§14） | 🚧 | 只有基礎設施：`seagent-kernel/src/outbound.rs`（Target 語法 local/origin/channel/webhook，1 個測試）＋`crates/seagent/src/outbound_host.rs`（channel 與 HMAC webhook POST，1 個測試，已在 main.rs:341 `install`）。但 **Job 仍然沒有 deliver 欄位，沒有任何程式呼叫 `outbound::deliver`**，也沒有 failure_deliver |
| cron 技能/腳本/no_agent | cron/scheduler_script.py（H§14） | ⬜ | — |
| cron prompt 威脅掃描 | tools/cronjob_prompt_scan.py（H§14） | ⬜ | — |
| cron incidents / runs / notepad / monitor | cron/incidents.py 等（H§14） | 🚧 | 既有，未改動：只有 last_run／last_result |
| cron 每工作預算 | cron/quota_hold.py（H§14） | ✅ | 既有，未改動：Job.budget |
| cron 外部供應商 chronos | plugins/cron_providers/chronos（H§14） | ⬜ | — |
| 自動化建議 | cron/suggestions.py（H§14） | ⬜ | — |
| Goals（Ralph loop） | hermes_cli/goals.py（H§14） | ✅ | 既有，未改動 |
| Subgoals | hermes_cli/goal_command.py（H§14） | ⬜ | — |
| Session heartbeat | hermes_cli/heartbeat.py（H§14） | 🚧 | 既有的近似做法 `@every --reuse`。新增的 `wake.rs`（系統事件佇列，1 個測試）、`hooks::heartbeat_prompt`（runner.rs 有測試）**沒有心跳執行器使用** |
| /loop | hermes_cli/loops.py（H§14） | 🚧 | 既有，未改動：schedule @every |
| 外送 webhooks（hooks.outbound） | agent/outbound_webhooks.py（H§14） | 🚧 | `crates/seagent/src/hooks_outbound.rs`：佇列、HMAC `X-SE Agent-Signature-256`、5xx 重試，3 個測試（`signed_delivery_with_retry_on_5xx` 等），但 **main.rs 缺 `mod hooks_outbound`，沒有被編譯**。parked/wt-hooks main.rs 有 mod，可補（合併後 ✅） |
| shell hooks | agent/shell_hooks.py（H§14） | 🚧 | **退步**：ext.rs:86 改成呼叫 `crate::hooks_ext::load`，但這個模組沒宣告，原本可用的 shell hooks 路徑壞了。首次同意（consent，hooks_ext 測試 `consent_allowlist_opt_ins_and_revoke`）在 parked/wt-hooks 可補 |
| 週期維護排程器 | agent/periodic_scheduler.py（H§14） | N/A | Python 執行緒細節（盤點原判） |

### H§8／§9 相關斜線與 CLI

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| /heartbeat (/hb) | hermes_cli/commands.py（H§8） | 🚧 | 既有，未改動：只有 schedule 近似 |
| /loop | hermes_cli/commands.py（H§8） | 🚧 | 既有，未改動 |
| /subgoal | hermes_cli/commands.py（H§8） | ⬜ | — |
| /cron | hermes_cli/commands.py（H§8） | ✅ | 既有，未改動：`seagent schedule` |
| /kanban | hermes_cli/commands.py（H§8） | ⬜ | 沒有 slash 指令，也沒有 `seagent kanban` CLI（main.rs／commands.rs 沒有 kanban） |
| /goal | hermes_cli/commands.py（H§8） | ✅ | 既有，未改動：`seagent goal` |
| cron list/create/edit/…/doctor/tick | hermes_cli/subcommands/cron.py（H§9） | 🚧 | 既有，未改動：沒有 edit/runs/incidents/notepad/doctor |
| hooks list/test/revoke/doctor | hermes_cli/subcommands/hooks.py（H§9） | 🚧 | `crates/seagent/src/hooks_cli.rs`（list/test/approve/revoke/doctor/info/enable/disable/check/install，2 個測試），main.rs 已有 `"hooks"` 分派與說明文字，但 **缺 `mod hooks_cli` → 無法編譯**。parked/wt-hooks 可補 |
| webhook subscribe/list/remove/test | hermes_cli/subcommands/webhook.py（H§9） | 🚧 | main.rs `cmd_webhook` 新增 `test`（簽章測試 `webhook_test_signs_like_github_against_a_fake_listener` 在 hooks_cli.rs），但呼叫的 `hooks_cli::` 未宣告，原本 ✅ 的 `seagent webhook` 也跟著無法編譯。parked/wt-hooks 可補 |
| send | hermes_cli/send_cmd.py（H§9） | ✅ | 既有，未改動：`seagent channel send` |

---

## OpenClaw

### O§1 核心工具（cron／message／gateway／canvas 相關列）

共通狀況：`seagent-app/src/surfaces/` 由 `pub mod surfaces`（seagent-app lib.rs）宣告，`surfaces::tools()` 已接到 main.rs `build_agent`，ARP 方法、HTTP 路由與 `spawn_daemon` 接到 `cmd_daemon`，web 端有 `ui/web/surfaces.js`（ui.rs `/ui/surfaces.js`）。**但 `Config` 沒有 `surfaces` 欄位**（`surfaces/mod.rs:84`），seagent-app 無法編譯。parked/wt-surfaces 的 config.rs 有這個欄位：只要補上一行，以下各列（canvas／show_widget／dashboard／gateway／progress_card／lobster／diffs／file_transfer／team_reports）就會是 ✅。

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| canvas | extensions/canvas/src/tool.ts（O§1） | 🚧 | surfaces/canvas.rs：present/hide/navigate/eval/snapshot/a2ui_push/a2ui_reset；托管文件採能力 URL＋CSP；A2UI v0.8/0.9 驗證與渲染器；node 端透過 DevTools（node.rs 新增 canvas.* 指令）。4 個測試（`a2ui_jsonl_rules`、`linux_node_canvas_over_devtools`…）。缺 `cfg.surfaces` → parked 可補 |
| show_widget | src/canvas/widget-tool.ts（O§1） | 🚧 | surfaces/widgets.rs `ShowWidget`，測試 `inline_widget_is_hosted_and_rendered_by_the_ui`。缺 `cfg.surfaces` |
| dashboard | src/agents/tools/dashboard-tool.ts（O§1） | 🚧 | widgets.rs `DashboardTool`，session board 與 tabs，測試 `pinned_widgets_reports_and_dashboard_layout`。缺 `cfg.surfaces` |
| message | src/agents/tools/message-tool-*.ts（O§1） | 🚧 | 只有 channel 端：`Channel::message_action/message_actions`（lib.rs），discord（poll/reactions/read/pin/thread/search/moderation…，12 個測試）、slack（10 個動作，6 個測試）、telegram（7 個動作，6 個測試）、`action_args.rs`（2 個測試）。**沒有模型可呼叫的 `message` 工具**：沒有任何程式呼叫 `message_action`，lib.rs 註解提到的 `message::normalize_poll` 模組不存在；send/edit/delete 也沒有統一入口，`channel_send` 仍然只能送文字。其他 channel 都沒實作 |
| heartbeat_respond | src/agents/tools/heartbeat-response-tool.ts（O§1） | ⬜ | 沒有心跳執行 |
| automations (cron) | src/agents/tools/cron-tool*.ts（O§1） | ⬜ | 沒有工具。`wake.rs` 只是佇列，沒有呼叫者 |
| gateway | src/agents/tools/gateway-tool.ts（O§1） | 🚧 | surfaces/gateway.rs：config.get/config.schema.lookup/config.patch（需 baseHash、禁止碰 gates/hooks）、restart、update.run（拒絕 channel session），2 個測試。缺上游 `config.apply`；缺 `cfg.surfaces` |
| progress_card | src/agents/tools/progress-card-tool.ts（O§1） | 🚧 | surfaces/cards.rs：存檔，並鏡像到 chat 原地編輯，測試 `card_is_stored_mirrored_to_the_chat_and_edited`。缺 `cfg.surfaces` |
| conversations_list | src/agents/tools/conversation-tools.ts（O§1） | ⬜ | 既有，未改動 |
| conversations_send | 同上（O§1） | 🚧 | 既有，未改動：`channel_send` 只能送文字 |
| conversations_turn | 同上（O§1） | ⬜ | 既有，未改動 |

### O§2 外掛工具（非 browser、非媒體）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| lobster | extensions/lobster（O§2） | 🚧 | surfaces/lobster.rs（1,710 行）：管線各 stage、approve/ask 檢查點與 resume、workflow 檔、`llm.invoke`、`seagent.invoke`，5 個測試＋yaml.rs。缺 `cfg.surfaces` → parked 可補 |
| diffs | extensions/diffs（O§2） | 🚧 | surfaces/diffs.rs：view（能力 URL＋TTL）與 file（headless Chromium 輸出 PNG/PDF），4 個測試。缺 `cfg.surfaces` |
| workboard_*（≈40 工具） | extensions/workboard（O§2） | 🚧 | `kanban/workboard.rs` 定義了 39 個 `workboard_*` 名稱與 `all_tools()`/`worker_tools()`，但 **沒有任何地方註冊（未接線）**，**workboard/tests.rs 空** |
| file_fetch / dir_list / dir_fetch / file_write | extensions/file-transfer（O§2） | 🚧 | surfaces/file_transfer.rs ＋ node.rs 端（read_roots/write_roots），3 個測試（`tools_round_trip_through_a_node` 等）。缺 `cfg.surfaces` |
| feishu_*（doc/wiki/drive/bitable/perm/chat/msg） | extensions/feishu/src（O§2） | ⬜ | parked 只有 action_args，沒有飛書工具 |
| whatsapp_login / whatsapp_call | extensions/whatsapp（O§2） | ⬜ | — |
| zalouser tool | extensions/zalouser（O§2） | ✅ | 既有，未改動（盤點誤列 ⬜）：`seagent-channel/src/zalouser.rs:675` `tools()`，測試在 zalouser.rs:894 附近 |
| discussion（clickclack） | extensions/clickclack（O§2） | ⬜ | clickclack.rs 沒有 `tools()` |
| team-reports | extensions/team-reports（O§2） | 🚧 | surfaces/team_reports.rs：GitHub＋Discord 收集、日/週/月彙整、排程、ARP 與網頁，3 個測試（fake server）。缺 `cfg.surfaces` |
| session-share | extensions/session-share（O§2） | ⬜ | — |
| logbook | extensions/logbook（O§2） | ⬜ | — |
| mcp_events | extensions/mcp-events（O§2） | ✅ | 既有，未改動：seagent-plugin/src/events.rs |

（不計入本串流：llm-task 屬 agents 串流。不過 w 已有 `surfaces/llm_task.rs`，2 個測試，接線方式同上，也缺 `cfg.surfaces`。）

### O§8 執行期功能（heartbeat／hooks／flows／boards）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| Cron/automations（announce、webhook delivery、isolated vs main、wake） | src/cron（O§8） | 🚧 | 既有排程未改動。outbound.rs/outbound_host.rs 投遞層與 wake.rs 佇列都存在，但沒有接到 Job／排程器；沒有 `@at` 一次性；`hooks::fire_cron_changed` 從未被呼叫 |
| Heartbeat（active hours、delivery、prompt contributions） | src/infra/heartbeat-*.ts（O§8） | ⬜ | 沒有執行器。`wake.rs`、`hooks::heartbeat_prompt/heartbeat_contribution` 只是零件，沒有使用者；config `heartbeat` 是空骨架 |
| Hooks：before_model_resolve … before_agent_finalize | src/plugins/hook-types.ts（O§8） | 🚧 | kernel/hookpoints.rs（已用 `mod hookpoints` 宣告）＋kernel.rs 呼叫點都在，runner.rs 有 4 個測試（`before_model_resolve_overrides_model_and_fallbacks_for_the_turn` 等）。但 **hooks.rs 少了這些變體，seagent-kernel 無法編譯** → parked/wt-hooks hooks.rs 可補（合併後 ✅） |
| Hooks：model_call / llm_input/output | 同上（O§8） | ✅ | 既有，未改動：PreModel/PostModel |
| Hooks：before/after_compaction | 同上（O§8） | ✅ | 既有，未改動 |
| Hooks：before/after_tool_call、tool_result_persist | 同上（O§8） | ✅ | 既有，未改動 |
| Hooks：message_received/sending/sent、inbound_claim、before_dispatch、reply_dispatch | 同上（O§8） | 🚧 | ext.rs:909/968/980 呼叫 `hooks_ext::inbound_claim/before_dispatch/reply_dispatch`（測試 `channel_pipeline_hook_points`），但 enum 缺變體，且 hooks_ext 未宣告 → parked/wt-hooks 可補 |
| Hooks：session_start/end、before_reset、agent_end | 同上（O§8） | ✅ | 既有，未改動（SessionStart/SessionEnd/TurnEnd）。新增的 before_reset（kernel.rs `end_session`）屬於下面「misc」列的損壞 |
| Hooks：subagent_spawned/progress/ended/delivery_target | 同上（O§8） | 🚧 | kernel.rs spawn 路徑呼叫 `subagent_progress`/`subagent_delivery_target`，經 ext.rs `ChannelRoutes`（HostRoutes）投遞，測試 `subagent_progress_delivery_target_and_before_reset`。enum 缺變體 → parked 可補 |
| Hooks：gateway_start/stop | 同上（O§8） | ✅ | 既有（基底已有 DaemonStart/DaemonStop，盤點 🚧 是誤判），e2e `tests/e2e/run.py:1098`；本次只加了 `reason` 欄位 |
| Hooks：cron_changed/reconciled、skill_changed、heartbeat_prompt_contribution、before_install、resolve_exec_env、channel_pairing_requested、before_message_write | 同上（O§8） | 🚧 | skill_changed（hooks_ext 監看執行緒，測試 `skill_changes_detect_create_update_remove`）、before_install（hooks_cli install）、resolve_exec_env／before_message_write（hookpoints，runner 測試）、channel_pairing_requested（ext.rs:840）在 parked/wt-hooks 是完整的。**cron_changed/cron_reconciled 即使在 parked 也從未被觸發**（automation.rs 沒有呼叫 `fire_cron_*`）；**heartbeat_prompt_contribution 沒有心跳執行器** |
| Bundled hooks：boot-md、bootstrap-extra-files、command-logger、compaction-notifier、session-memory | src/hooks/bundled/*（O§8） | 🚧 | `crates/seagent/src/hooks_bundled.rs` 5 個全部實作，5 個測試＋hooks_ext `session_memory_and_boot_md_against_a_kernel`；**缺 `mod hooks_bundled`** → parked/wt-hooks 可補 |
| Gmail watcher hook | src/hooks/gmail*.ts（O§8） | 🚧 | `crates/seagent/src/gmail_hook.rs`：users.watch、Pub/Sub push、history，4 個測試（fake Google）；**缺 `mod gmail_hook`** → parked 可補 |
| Session auto-reset（idle/daily） | src/hooks/session-auto-reset.ts（O§8） | 🚧 | hooks_ext `auto_reset`（ext.rs:915），測試 `reset_policy_resolution_matches_openclaw`、`auto_reset_replaces_stale_channel_sessions`；**hooks_ext 未宣告** → parked 可補 |
| Polls | src/polls.ts（O§8） | 🚧 | discord `poll`（測試 `poll_validates_and_registers_votes`）、telegram `poll`（`poll_maps_to_send_poll_and_validates`）、`action_args::poll_fields`。缺 message 工具與 `normalize_poll`，模型無法使用；其他 channel 無 |
| Boards（session/GitHub boards、website） | src/boards（O§8） | 🚧 | kanban/widget_board.rs、sessions_board.rs（ARP `board.*`，各 1 個測試，受 cfg.kanban 型別錯誤阻擋）＋surfaces/widgets.rs session boards（`session:report/progress/website`，缺 `cfg.surfaces`）。兩套 board 實作重疊 |
| Flows（channel setup、model picker、doctor…） | src/flows（O§8） | 🚧 | 既有，未改動：只有 `seagent setup`。lobster 工作流見 O§2 |
| Session cards / progress cards | src/session-cards（O§8） | 🚧 | surfaces/cards.rs（見 progress_card），缺 `cfg.surfaces` |

### O§5／§6 相關斜線與 CLI

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| /loop | commands-registry.shared.ts（O§5） | ⬜ | — |
| /dashboard | 同上（O§5） | ⬜ | 有 dashboard 工具，但沒有 slash 指令 |
| /workboard, /card | extensions/workboard（O§5） | ⬜ | — |
| message send/read/react/poll/pin/thread/edit/delete | src/cli/program/message（O§6） | 🚧 | 既有，未改動：`seagent channel send` 只能送文字；channel `message_action` 沒有接到 CLI |
| system（events/heartbeat/presence） | src/cli/system-cli.ts（O§6） | ⬜ | wake.rs 註解提到 `seagent system event`，但 CLI 不存在 |
| cron / automations | src/cli/cron-cli（O§6） | ✅ | 既有，未改動：`seagent schedule` |
| hooks | src/cli/hooks-cli.ts（O§6） | 🚧 | hooks_cli.rs（含 hook pack install --link、check、enable/disable），缺 `mod hooks_cli` → parked 可補 |
| webhooks（Gmail Pub/Sub helpers） | src/cli/webhooks-cli.ts（O§6） | 🚧 | `seagent webhook test` 已加但無法編譯；沒有 Gmail setup 輔助指令（gmail 只靠設定檔） |

---

## 暫存目錄（parked）內容

總結：**parked 裡沒有任何 w-automation 缺少的新檔案。** 所有新增檔案都已逐字存在於 w。差別只在共用檔（hooks.rs、main.rs、config.rs、ext.rs）合併時被覆蓋或遺漏。parked 真正的價值是提供那幾個共用檔的「正確版本」。

| 目錄 | 類型 | 與 w-automation 差異 | 功能 | 完整度 | 與 w 的衝突 |
|---|---|---|---|---|---|
| wt-hooks | worktree | 不同：`seagent-kernel/src/hooks.rs`（多 19 個 HookEvent 變體與 name 對應）、`crates/seagent/src/main.rs`（有 5 行 `mod gmail_hook/hooks_bundled/hooks_cli/hooks_ext/hooks_outbound`；沒有 surfaces 與 outbound_host 接線）、`config.rs`（`hooks_extra`＋PROJECT_GATED 含 hooks_extra，沒有 w 的骨架欄位）、`ext.rs`（沒有 `channel_map`）、Cargo.lock。其餘（hookpoints.rs、kernel.rs、runner.rs、hooks_*.rs、gmail_hook.rs、args.rs、e2e）與 w 相同 | OpenClaw 全部 hook 點、首次同意、bundled hooks、outbound webhooks、gmail、auto-reset、hooks CLI、webhook test | 自身看起來完整，有測試（hooks.rs 7、hooks_ext 11、bundled 5、gmail 4、outbound 3、cli 2、runner 新增 8）。cron_changed/heartbeat 只做了 helper、沒有觸發點 | 修法：hooks.rs 直接用 wt-hooks 版（它是 w 版的超集）；main.rs 只加 5 行 mod；config PROJECT_GATED 補 `hooks_extra`。不要整檔覆蓋 main.rs/config.rs/ext.rs，否則會丟掉 surfaces／outbound_host 接線 |
| wt-kanban | worktree | kanban/ 23 檔全部與 w 相同；不同的是 `config.rs`（`pub kanban: crate::kanban::KanbanConfig`，gated 含 kanban）與 `lib.rs`（沒有 outbound/wake）、Cargo.lock | Hermes kanban 15 工具、派工器、多板、PR 驗收、workboard 39 工具 | 4 個 tests.rs 子檔是空的（只有 `use super::*;`）；orchestrator 工具與 workboard 工具都沒註冊；swarm/transfer 沒有呼叫者。合併後仍是 🚧 | 只需把 w config.rs 的 `kanban: toml::Table` 改成 `KanbanConfig`（w 那個欄位是骨架，沒有其他使用者） |
| wt-platform | worktree | 5 個檔案（action_args、discord.rs、discord_actions、discord_tools、lib.rs）全部與 w 相同 | discord／discord_admin 工具、discord message_action | 完整，有測試 | 無（已完整併入） |
| wt-surfaces | worktree | surfaces/ 11 檔、ui/web、node.rs、ui.rs 與 w 相同；不同的是 `config.rs`（`pub surfaces: toml::Table`）、ext.rs/main.rs（w 多了 hooks 與 outbound 的改動，surfaces 部分相同）、Cargo.lock | canvas/A2UI、show_widget、dashboard、progress_card、gateway、lobster、llm-task、diffs、file-transfer、team-reports | 完整，有測試（約 33 個）。只差 config 一個欄位 | 只需在 w config.rs 補 `pub surfaces: toml::Table`，無其他衝突 |
| wtp-chat1 | 純副本（自帶 .git，基底 5c369e5） | 新增/修改的 action_args.rs、lib.rs、slack.rs、slack_actions.rs、telegram.rs、telegram_actions.rs 全部與 w 相同；其餘差異都是基底較舊（沒有 w 的其他改動） | slack/telegram message_action | 完整，有測試；沒有 message 工具 | 無 |
| wtp-chat2 | 純副本 | 只有 action_args.rs＋lib.rs，與 w 相同 | message_action trait 骨架 | 只是骨架 | 無 |
| wtp-discord | 純副本 | discord.rs、discord_actions.rs、discord_tools.rs 與 w 相同 | 同 wt-platform | 完整 | 無 |
| wtp-feishu | 純副本 | 只有 action_args.rs＋lib.rs（與 w 相同） | 原意是飛書工具 | **沒有飛書程式**（工作未開始） | 無 |
| wtp-feishu2 | 純副本 | 同 wtp-feishu | 同上 | 沒有飛書程式 | 無 |
| wtp-tools | 純副本 | 只有 action_args.rs＋lib.rs（與 w 相同） | 原意不明（可能是 message 工具） | **沒有 message 工具** | 無 |

---

## 剩餘缺口（依使用者影響排序）

1. 【全域】合併損壞：hooks.rs 少 19 個 HookEvent 變體、main.rs 缺 5 個 mod 宣告、config 的 `kanban` 型別錯誤、缺 `surfaces` 欄位。整個 workspace 無法編譯，既有的 shell hooks 與 `seagent webhook` 也因此退步。PROJECT_GATED 缺 `hooks_extra`（安全問題）。
2. automations／cronjob 模型工具（O§1 automations、H§1 cronjob_manage）：完全沒有，無 add/update/remove/list/run/runs/wake。
3. cron 投遞（H§14 deliver/failure_deliver、O§8 announce/webhook）：outbound.rs 投遞層已存在，但 Job 沒有 deliver 欄，也沒人呼叫 deliver；沒有 `@at` 一次性排程。
4. message 工具（O§1 message）：沒有模型工具。channel 端只有 discord/slack/telegram 的擴充動作；`normalize_poll` 不存在；send/edit/delete/react 沒有統一入口；其他 channel 沒實作。
5. Heartbeat（O§8 Heartbeat、O§1 heartbeat_respond、H§14 Session heartbeat、H§8 /heartbeat）：沒有執行器、active hours、投遞與回應工具；wake.rs 只是佇列。
6. Kanban 工具層（H§5 共 11 列工具）：tools/tests.rs 空，沒有工具層測試；orchestrator 工具（kanban_list/unblock）未註冊給任何 session。
7. Kanban 派工器（H§5）：dispatch/tests.rs 空；沒有 `seagent kanban` CLI、`/kanban`（H§8）。
8. workboard_*（O§2）：39 個工具未註冊，workboard/tests.rs 空。
9. Surfaces 九項（canvas、show_widget、dashboard、gateway、progress_card、lobster、diffs、file transfer、team-reports，以及 O§8 session cards）：只差 config `surfaces` 欄位；gateway 缺 config.apply。
10. Hooks 群（O§8 pre-run／message pipeline／subagent／misc／bundled／gmail／auto-reset、H§14 outbound webhooks／shell hooks、H§9／O§6 hooks CLI 與 webhook test）：parked/wt-hooks 可補。補完後仍缺 cron_changed/cron_reconciled 觸發點與 heartbeat contribution 執行器。
11. Polls（O§8）：只有 discord/telegram，模型無法使用（沒有 message 工具）。
12. 飛書工具（H§3 feishu_doc_read、feishu_drive_*×4、O§2 feishu_*）：完全沒有，parked 也沒有。
13. kanban decompose/specify（H§5）：llm/tests.rs 空，只能經 ARP。
14. kanban 多看板轉移（H§5）：transfer.rs 未接線、沒有 CLI；swarm.rs 未接線。
15. kanban 儀表板（H§5）：沒有 web UI 頁面；Boards（O§8）有兩套重疊實作，且受合併損壞阻擋。
16. kanban PR acceptance（H§5）：受 cfg 型別錯誤阻擋，工具路徑無測試。
17. conversations_list／conversations_turn ⬜、conversations_send 🚧（O§1）：未改動。
18. message CLI（O§6）：`seagent channel send` 只能送文字，`message_action` 沒接 CLI。
19. system CLI（O§6 events/heartbeat/presence）：不存在。
20. /loop（H§8、H§14、O§5）、/dashboard、/workboard、/card（O§5）、/subgoal 與 Subgoals（H§8、H§14）：不存在或只有 schedule 近似。
21. cron 技能/腳本/no_agent、prompt 威脅掃描、incidents/runs/notepad、chronos、自動化建議（H§14）；cron CLI 缺 edit/runs/incidents/notepad/doctor（H§9）。
22. 元寶工具 ×5、Google Meet ×5、Teams 會議管線（H§3）：完全沒有（config 只有 `meetings` 空骨架）。
23. whatsapp_login/whatsapp_call、discussion（clickclack）、session-share、logbook（O§2）：完全沒有。
24. Flows（O§8）：只有 `seagent setup`。webhooks CLI（O§6）沒有 Gmail setup 輔助指令。
25. context_engine 執行期工具（H§3）：engine 沒有自帶工具的通道（未改動）。
