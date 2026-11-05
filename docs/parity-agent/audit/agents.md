# 稽核：agents 工作流

- 工作流：agents（委派／子代理、session 工具、多代理、clarify、session_search、對話倒帶／checkpoint、MoA、structured_output／llm-task／decision_evaluate、其他代理層功能、相關斜線/CLI）
- 目錄：`$R/w-agents`（基準 commit 5c369e5，全部為未提交工作）
- 編譯/測試：`cargo build --workspace --all-targets` 成功；`cargo test --workspace --no-fail-fast` 通過 820、失敗 4、忽略 2。失敗：`coderun::tests::{script_output_exit_codes_and_nested_protocol,failures_timeout_cancel_and_bad_lang}` 兩個失敗是稽核環境造成（TMPDIR 路徑過長，unix socket 超過 SUN_LEN），五個副本含 SE Agent 都一樣，非本流迴歸；`seagent-tools lsp::tests::roots_gating_and_trust` 也是環境造成（TMPDIR 位於使用者家目錄的 git repo 內，nogit 目錄被判成在 repo 裡）；**`seagent-kernel decision::tests::openai_decisions_against_fake_server` 是真實缺陷**：choice 的 probabilities 依 criteria 物件鍵序對應，serde_json 未開 preserve_order，鍵被排序成 high/low，結果 choice 回 "low"（預期 "high"）。原始輸出：`audit/agents-tests.txt`。
- 判定只依程式碼；`docs/parity-agent/agents.md` 不存在（前任 worker 未寫）。

## 差異範圍

- 修改 20 檔（+1204/−98）：Cargo.lock、THIRD_PARTY_NOTICES.md、seagent-app/tui.rs、seagent-core/tool.rs、seagent-kernel/{Cargo.toml, approver, checkpoint, config, daemon, event, hooks, kernel, lib, projection}.rs、seagent-tools/{fs, lib}.rs、seagent/{args, ext, main}.rs、tests/e2e/run.py。
- 新增（未追蹤）：seagent-kernel/src/{agents, decision, devprompts, jsonschema, moa, reactions, subagents(1356 行), trajectory, verify, worktree}.rs；seagent-tools/src/lsp.rs；seagent/src/{devtools, export, export_icons, mcp_presets}.rs、export_template.html、mcp_presets.json；docs/parity-agent/（只有兩份盤點）。
- 新依賴：seagent-kernel 加 `ureq`（workspace 既有，decision provider HTTP 用）。
- 所有新模組皆有 `mod`/`pub mod` 宣告。**但**：沒有任何新的模型可呼叫工具被註冊——`delegate_task`、`sessions_*`、`agents_*`、`subagents`、`clarify`、`moa`…全無 ToolSchema/`impl Tool`；`LlmTask`、`DecisionEvaluate` 有 `impl Tool` 卻不在 `seagent_tools::builtin_tools()` 也不在 `kernel_tools()`。CLI 只新增 `lsp verify init plan` 與 `session export/trajectory/upload-trace/verify-export`、`checkpoint status/prune/clear`、`mcp presets`；無 `seagent agents/users/moa/worktree`，聊天無 `/undo N /retry /branch /moa /agents`。
- `crates/seagent-model/src/moa.rs` 在此副本**不存在**；MoA 實作在 seagent-kernel/src/moa.rs（未接線）。

## 統計

| 狀態 | 數量 |
|---|---|
| ✅ | 35 |
| 🚧 | 45 |
| ⬜ | 13 |
| N/A | 2 |
| 合計 | 95 |

## Hermes §1（委派／clarify／session_search 列）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| session_search | tools/session_search_tool.py（H§1） | 🚧 | kernel `session_search` 仍只有 query+limit（kernel.rs `kernel_tools`），store.rs 未改；無讀取/捲動模式、日期/角色篩選、摘要 |
| clarify | tools/clarify_tool.py, clarify_batch.py, clarify_gateway.py（H§1） | 🚧 | approver.rs 新增 `Approver::clarify`、`ClarifyQuestion`、`parse_answer`/`render_question`，`PendingItem::Question` 帶 choices/multi，daemon pending JSON 輸出 choices；測試 `clarify_tests::answers_map_onto_choices`、`pending_clarify_publishes_choices_and_times_out`。**無 clarify 工具**（ask_user 未改，`.clarify(` 只在測試被呼叫）；web UI 不渲染 choices；無 channel 卡片/按鈕送達 |
| delegate_task | tools/delegate_tool*.py（H§1） | 🚧 | `Runtime::delegate`（subagents.rs:544）支援多 spec、Sync/Background/Collect、output_schema、worktree、toolsets；但**無 `delegate_task` 工具**，唯一入口是既有 `spawn` → `Host::spawn_agent` 以單一 spec + `Mode::Sync` 呼叫 |

## Hermes §13 Checkpoint／回溯／Session 狀態

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| 檔案 checkpoint（shadow git） | tools/checkpoint_manager.py（H§13） | ✅ | checkpoint.rs；新增每回合 `EventKind::Checkpoint{id,turn}`（kernel.rs checkpoint 段）；測試 `snapshot_restore_roundtrip_including_new_and_deleted_files` |
| checkpoint 保留/修剪 | tools/checkpoint_maintenance.py, checkpoint_pruning.py（H§13） | ✅ | checkpoint.rs `Store::prune/status/maybe_auto_prune`、`Limits`；config `checkpoint.max_snapshots/max_total_size_mb/max_file_size_mb/auto_prune/retention_days/min_interval_hours`；daemon 每小時 auto-prune；CLI `seagent checkpoint status|prune|clear`（export.rs `cmd_checkpoint_store`）；測試 `prune_removes_orphans_stale_and_enforces_size`、`snapshot_limits_trim_history_and_skip_large_files`、`missing_parent_or_unrecorded_identity_is_not_an_orphan` |
| 對話 rewind | hermes_state_rewind.py（H§13） | 🚧 | `EventKind::Rewind{from_seq,turns}` + projection.rs:130 處理、`View.user_turns/checkpoints`；**沒有任何程式碼產生 Rewind 事件**，無 kernel API、無指令、無測試 |
| session 持久化＋FTS | hermes_state_*.py（H§13） | ✅ | 既有，未改動（store.rs） |
| session 匯出 HTML/MD | session_export_html.py, session_export_md.py（H§13） | ✅ | seagent/export.rs `cmd_export`（md/qmd/html/json、--out、--no-redact）、聊天 `/save` `/export-session`；測試 `markdown_has_frontmatter_messages_and_verifiable_digest`、`html_is_standalone_escaped_and_collapsible`、`json_export_shape` |
| session lost-and-found | session_lost_and_found.py（H§13） | N/A | SQLite 專屬；SE Agent JSONL 自修 |
| 崩潰後自動續跑 | session_recovery.py（H§13） | ✅ | 既有，未改動（daemon.rs） |
| 子代理 live log | tools/delegation_live_log.py（H§13） | 🚧 | subagents.rs `live_log` 在每次 `append` 寫子代理 `live.log`（遮蔽後）並發 SubagentProgress hook；經 spawn 可達，但**無測試**，spawn 回傳不含 live log 路徑（只有背景 handle 有 `live_transcript`） |
| 軌跡存檔 | agent/trajectory.py（H§13） | ✅ | seagent-kernel/trajectory.rs ShareGPT + `config.trajectory.save`（`seagent run` 後 `export::maybe_save_trajectory`）、`seagent session trajectory`；測試 `sharegpt_matches_hermes_shape`、`flatten_splits_tool_results_and_names_them` |
| HF trace 上傳 | agent/trace_upload.py（H§13） | ✅ | export.rs `upload_trace`/`hf_upload`、`seagent session upload-trace`、`/upload-trace`、`[trace]` 設定；測試 `hf_upload_creates_private_dataset_and_commits_the_trace`（本機假 hub）、`token_comes_from_the_vault`、trajectory `claude_code_trace_links_turns` |

## Hermes §15 委派／子代理

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| 同步子代理 | tools/delegate_tool.py（H§15） | ✅ | `spawn` → `Host::spawn_agent` → `Runtime::delegate(Mode::Sync)`（kernel.rs、subagents.rs）；既有測試 seagent-tools agent.rs `spawn_forwards_request`、seagent-kernel/tests/runner.rs delegate 測試（未改） |
| 批次 tasks[] | delegate_tool_tasks.py, delegate_tool_dispatch.py（H§15） | 🚧 | `delegate` 接 `Vec<ChildSpec>`、`max_concurrent_children`、群組排程（測試 `ready_buckets_respect_groups`）；無工具暴露 `tasks[]` |
| 背景（async）委派 | async_delegation*.py（H§15） | 🚧 | `Mode::Background/Collect`、`subagent_launch`、`await_children`/`close_run`/`recover_subagents` 已接進 `Runtime::run`、`auto_resume`；但沒有任何呼叫端能以背景模式啟動（無工具、無 daemon 設定 `auto_resume`），無測試 |
| 子代理 list/steer/stop | delegate_tool_registry.py（H§15） | 🚧 | `subagent_list/steer/stop/wait`（subagents.rs:1061–1111）**零呼叫端**、無測試 |
| output_schema 結構化輸出 | delegation_output_schema.py（H§15） | 🚧 | jsonschema.rs（`validate_output`、`output_contract`，測試 `output_contract_extraction_and_retry` 等 4 個）、delegate 內驗證重試；spawn 的 ChildSpec 不帶 schema，`spec_from` 只被測試呼叫 → 不可達 |
| worktree 隔離 | tools/subagent_worktree.py（H§15） | 🚧 | worktree.rs `create/finalize`（測試 `create_finalize_clean_dirty_and_committed`）由 delegate 使用；spawn 路徑不設 worktree → 不可達 |
| 子代理工具集限制 | delegate_tool_toolsets.py（H§15） | ✅ | spawn `tools`；新增 `EventKind::Tools` + `subagents::tool_allowed` 在 kernel 三處強制、`expand_tools` 工具集、`BLOCKED_FOR_CHILDREN`；測試 `toolsets_expand_and_policy` |
| fork 父對話 | delegate_tool.py（H§15） | ✅ | 既有 spawn `fork`（改走 delegate） |
| 子代理模型/憑證覆蓋 | delegate_tool_config.py（H§15） | ✅ | 既有，未改動（spawn `model`、`model.subagent`）；新 `[delegation]` 設定 |
| 深度上限 | delegate_tool_config.py（H§15） | ✅ | `runner.max_spawn_depth` 檢查移入 `delegate`；既有測試 |
| 成本彙整／預算共享 | delegate_tool_results.py（H§15） | ✅ | 既有，未改動（ledger.rs） |
| 子代理輸出遮蔽 | delegation_redaction.py（H§15） | ✅ | `entry.summary = vault.redact(..)`（subagents.rs:870）＋既有全域遮蔽 |
| 子代理生命週期 API（外掛） | agent/subagent_lifecycle.py（H§15） | 🚧 | hooks.rs 新增 `SubagentProgress`、`SubagentDelivery`（含 `subagent_delivery_target` 別名）；Progress 經 live_log 觸發，Delivery 只在不可達的背景路徑；無測試 |
| /review 獨立審查代理 | agent/review_engine.py（H§15） | ⬜ | 無 |
| 外部 ACP 代理委派 | copilot_acp_client（H§15） | ✅ | 既有，未改動（acp_delegate） |

## Hermes §23 其他代理層功能

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| LSP 整合 | agent/lsp/*（H§23） | ✅ | seagent-tools/lsp.rs（1250 行）接進 write/edit/patch（fs.rs `lsp::after_write`）、`devtools::configure_lsp`、`seagent lsp status|list|which|check|restart`；9 個測試如 `push_server_reports_only_new_errors`、`file_tools_append_new_diagnostics`；e2e `verify_lsp_init_plan` |
| verify 子系統 | agent/verify/*（H§23） | ✅ | seagent-kernel/verify.rs + `seagent verify`（devtools.rs `cmd_verify`）；測試 `detects_node_python_go_rust_java_make_compose`、`runner_phases_stop_on_failure_timeout_and_readiness`；e2e |
| /init AGENTS.md 產生 | hermes_cli/init_command.py（H§23） | ✅ | devprompts.rs `expand_builtin`；`seagent init`、聊天 `/init`、channel 內建指令（ext.rs）；測試 `init_prompt_generate_vs_update`；e2e |
| /learn | agent/learn_prompt.py（H§23） | ⬜ | 無（devprompts 只有 init/plan） |
| /plan 計畫模式 | agent/plan_prompt.py（H§23） | ✅ | devprompts.rs、`seagent plan`、`/plan`；測試 `plan_prompt_and_path`；e2e |
| 反應偵測（vibe） | agent/reactions.py（H§23） | ✅ | reactions.rs `detect`，接 `seagent chat`（♥）與 TUI；測試 `affection_fires_sentiment_does_not` |
| git worktree 管理 | hermes_cli/worktree_*.py（H§23） | 🚧 | worktree.rs list/prune/remove（測試 `list_prune_remove_and_errors`）；無 `seagent worktree` CLI／`/worktree` → 未接線 |
| 監控 OTLP 匯出 | agent/monitoring/*（H§23） | ⬜ | 無 |
| Google Meet 外掛 | plugins/google_meet（H§23） | ⬜ | 無（亦可能屬 media/平台工作流） |
| 記憶體回收 malloc_trim | hermes_cli/mem_trim.py（H§23） | N/A | Python/glibc 專屬 |
| optional-mcps（65 個預設） | optional-mcps/*（H§23） | ✅ | mcp_presets.json 65 筆（與上游數量相同）+ mcp_presets.rs、`seagent mcp presets [q]|presets show|add --preset --env`；測試 `catalog_is_complete_and_well_formed`、`blocks_are_valid_server_configs`、`env_values_inline_non_secrets_and_vault_secrets` |

## Hermes §8 斜線指令（本主題相關）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| /retry | hermes_cli/commands.py（H§8） | ⬜ | 無（Rewind 事件無人產生） |
| /undo N（對話回合） | hermes_cli/commands.py（H§8） | 🚧 | `/undo` 仍只是檔案 checkpoint 還原（main.rs 未改此段）；無回合倒帶 |
| /branch (/fork) | hermes_cli/commands.py（H§8） | 🚧 | 既有 `seagent session fork`；聊天內無、無依回合分支 |
| /worktree | hermes_cli/commands.py（H§8） | ⬜ | 無斜線；worktree.rs 只有函式庫 |
| /rollback | hermes_cli/commands.py（H§8） | ✅ | 既有，未改動（`/undo [id]`、`seagent checkpoint`） |
| /agents (/tasks) | hermes_cli/commands.py（H§8） | 🚧 | 未改；`subagent_list` 存在但無指令 |
| /review | hermes_cli/commands.py（H§8） | ⬜ | 無 |
| /plan | hermes_cli/commands.py（H§8） | ✅ | 聊天 `/plan`（main.rs cmd_chat）、devprompts 測試 |
| /moa | hermes_cli/commands.py（H§8） | 🚧 | moa.rs `moa_turn`/`moa_references` 存在但零呼叫端，無斜線指令；moa 測試只涵蓋 preset 儲存與 PII 過濾 |
| /learn | hermes_cli/commands.py（H§8） | ⬜ | 無 |
| /init | hermes_cli/commands.py（H§8） | ✅ | 聊天 `/init`、e2e |
| /bg | hermes_cli/commands.py（H§8） | 🚧 | 未改；只有 `seagent send` |
| /sessions | hermes_cli/commands.py（H§8） | ✅ | 既有，未改動 |

## Hermes §9 CLI 子指令（本主題相關）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| moa list/configure/delete | hermes_cli/subcommands/moa.py（H§9） | 🚧 | moa.rs `save_preset/delete_preset/set_default/effective`（測試 `presets_validate_save_and_merge`）；無 `seagent moa` CLI（BUILTINS 未加） |
| sessions（23 個子指令） | hermes_cli/subcommands/sessions.py（H§9） | 🚧 | 新增 export 多格式、trajectory、upload-trace、verify-export；仍無 rename/prune/archive/pin/stats/import/repair（Meta 事件有 pinned/archived 欄位但無 CLI） |
| checkpoints | hermes_cli/subcommands/checkpoints.py（H§9） | ✅ | `seagent checkpoint status|prune|clear`（export.rs `cmd_checkpoint_store`）＋ checkpoint.rs 測試 |
| worktree list/prune/restore | hermes_cli/worktree_cmd.py（H§9） | 🚧 | 函式庫有 list/prune/remove，無 CLI；無 restore |
| verify | hermes_cli/verify_cmd.py（H§9） | ✅ | `seagent verify`、e2e |
| lsp | agent/lsp/cli.py（H§9） | ✅ | `seagent lsp …`、e2e |

## OpenClaw §1（sessions/agents 列）＋ §2 llm-task

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| sessions（設定 label/pin/archive/group/patch/stop/clear） | src/agents/tools/sessions-tool.ts（O§1） | 🚧 | `EventKind::Meta{pinned,archived,group,status}` + projection 欄位、`Runtime::record`（可對執行中 session 寫設定）；無工具、無 CLI 產生 Meta |
| sessions_create | sessions-create-tool.ts（O§1） | 🚧 | agents.rs `Runtime::create_agent_session` 存在但**零呼叫端**；無工具 |
| sessions_list | sessions-list-tool.ts（O§1） | 🚧 | 未改；仍只有 mcp serve 的 `seagent_sessions` |
| sessions_history | sessions-history-tool.ts（O§1） | 🚧 | 未改 |
| sessions_search | sessions-search-tool.ts（O§1） | ✅ | 既有，未改動（`session_search`） |
| sessions_send | sessions-send-tool.ts（O§1） | 🚧 | 未改；無 in-agent 跨 session 傳訊 |
| sessions_spawn | sessions-spawn-tool.ts（O§1） | 🚧 | `spec_from` 解析 agentId/runTimeoutSeconds/taskName/context=fork（測試 `spec_parsing`）、delegate 依 agentId 套用 agent；無工具 |
| agents_wait | agents-wait-tool.ts（O§1） | 🚧 | `subagent_wait` 存在，零呼叫端、無測試 |
| sessions_yield | sessions-yield-tool.ts（O§1） | 🚧 | `request_end_turn` + run loop `end_turn` 檢查存在；無工具呼叫它 |
| subagents（list/cancel/wait） | subagents-tool.ts（O§1） | 🚧 | `subagent_list/stop/wait`，零呼叫端 |
| session_status | session-status-tool.ts（O§1） | ⬜ | 無工具（只有內部 `record`） |
| agents_list | agents-list-tool.ts（O§1） | 🚧 | `agents::all`/`resolve` 存在；無工具 |
| ask_user | ask-user-tool.ts（O§1） | ✅ | 既有，未改動（seagent-tools agent.rs，測試 `ask_user_paths`） |
| decision_evaluate | src/agents/tools/decision-tool.ts（O§1） | 🚧 | decision.rs `DecisionEvaluate impl Tool`、`evaluate`、`openai_decisions`（測試 `openai_decisions_against_fake_server`、`batch_parsing_and_answer_checks`）；**未加入任何工具註冊表** → 模型看不到 |
| structured_output | structured-output-tool.ts（O§1） | 🚧 | kernel 動態加 `structured_output` 工具、驗證、`Structured` 事件、結束回合、nudge（kernel.rs:620/728/1174；測試 `structured_checks`）；但**沒有任何東西產生 `EventKind::OutputSchema`**（無 CLI 旗標/API）→ 永遠不出現 |
| llm-task | extensions/llm-task（O§2） | 🚧 | decision.rs `LlmTask impl Tool`、`llm_task`、`[llm_task]` 設定；未註冊、`llm_task` 函式無測試 |

## OpenClaw §8（多代理／session／子代理列）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| Steering queue / queue modes | src/agents/agent-steering-queue.ts（O§8） | 🚧 | 未改；固定 steer |
| Sub-agents（depth, announce, thread-bound, visible） | src/agents/subagents（O§8） | 🚧 | depth ✅；announce（completion_text + inbox）存在但只在不可達背景路徑；無 thread-bound/visible |
| Hooks: subagent_spawned/progress/ended/delivery_target | src/plugins/hook-types.ts（O§8） | 🚧 | 新 `SubagentProgress`/`SubagentDelivery` + 別名；無測試，Delivery 不可達 |
| Session auto-reset（idle/daily） | src/hooks/session-auto-reset.ts（O§8） | 🚧 | 未改；只有 retention_days |
| Decisions runtime | src/decisions（O§8） | 🚧 | decision.rs provider（OpenAI /decisions、`[decision]` 設定、假伺服器測試）；工具未註冊 |
| Multi-agent routing / bindings | src/routing（O§8） | 🚧 | agents.rs `AgentDef`、`Binding`、`route`（channel/account/peer/user 層級，測試 `route_tiers_user_wildcard_account`、`add_bind_route_and_delete`）、config `[agents.*]`/`[[bindings]]`；channel 路由（ext.rs/router.rs）**未呼叫 `route`**，無 CLI |
| Worktrees（per-session） | src/agents/worktrees, worktrees-cli.ts（O§8） | 🚧 | worktree.rs 函式庫＋測試；不可達（無 CLI、spawn 不用） |
| Workspace checkpoints / undo | （SE Agent extra）（O§8） | ✅ | 既有＋新修剪功能 |
| Trajectory export | src/trajectory（O§8） | ✅ | trajectory.rs bundle 格式、`seagent session trajectory --format bundle`、`/export-trajectory`；測試 `bundle_events_are_versioned_and_linked`、export `sharegpt_and_bundle_files` |
| Personal instructions per user / users registry | src/cli/users-cli.ts（O§8） | 🚧 | agents.rs `user_add/link/link_email/set_instructions/merge/remove/find_user`（測試 `users_registry`）；無 `seagent users` CLI，channel 入站不呼叫 `find_user`，只有零呼叫端的 `create_agent_session` 會套個人指令 |

## OpenClaw §5 聊天指令（本主題相關）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| /export-trajectory | commands-registry.shared.ts（O§5） | ✅ | `seagent chat` `/export-trajectory`（main.rs `chat_export`）→ `export::write_bundle` |
| /session | 同上（O§5） | ⬜ | 無 |
| /subagents | 同上（O§5） | ⬜ | 無 |
| /agents | 同上（O§5） | ⬜ | 無 |
| /steer (/tell) | 同上（O§5） | 🚧 | 未改；自動 steer，無指令 |
| /queue | 同上（O§5） | ⬜ | 無 |

## OpenClaw §6 CLI（本主題相關）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| agents add/delete/bind/set-identity | register.agent.ts（O§6） | 🚧 | agents.rs `add/update/delete/bind/unbind/parse_bind` 寫 `<config>/agents.toml`（有測試）；無 `seagent agents` CLI |
| users | src/cli/users-cli.ts（O§6） | 🚧 | 函式庫有、測試有；無 CLI |
| worktrees | src/cli/worktrees-cli.ts（O§6） | 🚧 | 函式庫有、測試有；無 CLI |
| sessions（list/cleanup/import） | register.status-health-sessions.ts（O§6） | ✅ | 既有，未改動 |
| checkpoint / undo | （SE Agent extra）（O§6） | ✅ | 既有＋status/prune/clear |

## 剩餘缺口（依使用者影響排序）

1. delegate_task 工具（H§1）：完全沒有模型可見的 `delegate_task`；`Runtime::delegate` 只透過 spawn 單任務同步呼叫。
2. sessions_spawn（O§1）：無工具；背景生成、agentId、announce 都不可達。
3. 背景委派（H§15）：Background/Collect 模式無任何入口，daemon 未設 `auto_resume`，無測試。
4. 子代理 list/steer/stop（H§15）：`subagent_list/steer/stop` 零呼叫端、無測試。
5. subagents 工具（O§1）：無 list/cancel/wait 工具。
6. agents_wait（O§1）：`subagent_wait` 無工具、無測試。
7. sessions_yield（O§1）：`request_end_turn` 無工具呼叫。
8. 批次 tasks[]（H§15）：多 spec 能力無工具參數暴露。
9. output_schema（H§15）：spawn 不帶 schema；`spec_from` 只在測試用。
10. clarify（H§1）：`Approver::clarify` 無工具呼叫；web UI／channel 不渲染選項。
11. structured_output（O§1）：沒有任何方式設定 `OutputSchema`，工具永不出現。
12. decision_evaluate（O§1）：`DecisionEvaluate` 未註冊。
13. llm-task（O§2）：`LlmTask` 未註冊、`llm_task` 無測試。
14. Decisions runtime（O§8）：同上，provider 存在但不可用。
15. 對話 rewind（H§13）：Rewind 事件無產生者、無 kernel API、無測試。
16. /undo N（H§8）：仍只還原檔案。
17. /retry（H§8）：無。
18. /branch（H§8）：聊天內無、無依回合分支。
19. Multi-agent routing/bindings（O§8）：`agents::route` 未接到 channel 路由；無 CLI。
20. agents add/delete/bind（O§6）：無 `seagent agents` CLI。
21. sessions_create（O§1）：`create_agent_session` 零呼叫端，無工具。
22. agents_list（O§1）：無工具。
23. sessions_list（O§1）：無 in-agent 工具。
24. sessions_history（O§1）：無 in-agent 工具。
25. sessions_send（O§1）：無 in-agent 工具。
26. sessions（設定）（O§1）：Meta 事件無產生者、無工具／CLI。
27. session_status（O§1）：無。
28. session_search 模式（H§1）：無 read/scroll/篩選/摘要。
29. users registry（O§8）：無 CLI，channel 不辨識使用者。
30. users CLI（O§6）：無。
31. /moa（H§8）：`moa_turn` 零呼叫端，無斜線指令、無 turn 層級測試。
32. moa CLI（H§9）：無 `seagent moa`。
33. worktree 隔離（H§15）：spawn 不建 worktree。
34. Worktrees per-session（O§8）：不可達。
35. git worktree 管理（H§23）：無 CLI。
36. worktree list/prune/restore（H§9）：無 CLI、無 restore。
37. worktrees CLI（O§6）：無。
38. /worktree（H§8）：無。
39. Sub-agents announce/thread-bound/visible（O§8）：announce 不可達；無 thread-bound/visible。
40. 子代理生命週期 hooks（H§15）：新 hook 無測試，Delivery 不可達。
41. Hooks subagent_*（O§8）：同上。
42. 子代理 live log（H§13）：無測試；spawn 回傳不含路徑。
43. Steering queue modes（O§8）：仍固定 steer。
44. /queue（O§5）：無。
45. /steer（O§5）：無指令。
46. /agents（H§8）：無子代理面板。
47. /agents（O§5）：無。
48. /subagents（O§5）：無。
49. /session（O§5）：無。
50. /bg（H§8）：聊天內無。
51. sessions 23 子指令（H§9）：無 rename/prune/archive/pin/stats/import/repair。
52. /review（H§8）與 /review 審查代理（H§15）：無。
53. /learn（H§23、H§8）：無。
54. Session auto-reset（O§8）：只有 retention 刪除。
55. 監控 OTLP 匯出（H§23）：無。
56. Google Meet 外掛（H§23）：無（可能屬其他工作流）。
