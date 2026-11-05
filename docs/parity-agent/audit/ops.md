# 稽核：ops 工作流

- 工作流：ops
- 目錄：`$R/w-ops`（基準 commit 5c369e5，未提交工作）
- 編譯/測試：建置成功；測試通過 805、失敗 2、忽略 2。失敗只有 `coderun::tests::{script_output_exit_codes_and_nested_protocol,failures_timeout_cancel_and_bad_lang}` 兩個失敗是稽核環境造成（TMPDIR 路徑過長，unix socket 超過 SUN_LEN），五個副本含 ark 都一樣，非本流迴歸。e2e 未跑。原始輸出：`audit/ops-tests.txt`。
- 差異範圍：`git diff --stat HEAD` 40 檔、+8919/−204。全部新檔已 `git add`（狀態 A），無未追蹤檔。
  - 修改：`crates/ark/src/{main.rs,ext.rs,args.rs}`、`crates/ark-kernel/src/{config.rs,kernel.rs,event.rs,lib.rs,projection.rs}`、`crates/ark-kernel/tests/runner.rs`、`crates/ark-channel/src/{lib.rs,telegram.rs,discord.rs,zlib.rs}`、`crates/ark-app/src/lib.rs`
  - 新檔：`crates/ark/src/slash.rs`（1604 行，共用斜線指令表）、`crates/ark/src/testkit.rs`、`crates/ark/src/ops/*`（archive, backup, batch, completion, confcli, doctor, envfile, evals, logs, migrate, mod, net, profile, secretsrc, service, slashops, status, telemetry, ui_methods, update）、`crates/ark-kernel/src/queue.rs`、`crates/ark-app/src/clip.rs`、兩份 inventory
  - **佔位空殼（12 行、`COMMANDS = &[]`、`dispatch` 回 `None`）**：`ops/batch.rs`、`ops/doctor.rs`、`ops/evals.rs`、`ops/secretsrc.rs`、`ops/status.rs`、`ops/telemetry.rs`；`ops/ui_methods.rs` 的 `methods()` 回 `Arc::new(|_,_| None)`（宣稱提供 `command.list`/`logs.tail`，實際由 `slash::methods`/`logs::methods` 提供）。
  - `ui/web/*`、`crates/ark/src/setup.rs`、`crates/ark-app/src/tui.rs` **未改動**。
- 計數（僅本流列）：✅ 119 · 🚧 41 · ⬜ 76 · N/A 17 · 合計 253（另有 131 列屬其他工作流，見文末，不計入）

| 段落 | ✅ | 🚧 | ⬜ | N/A | 合計 |
|---|---|---|---|---|---|
| H§8 斜線指令 | 36 | 9 | 8 | 6 | 59 |
| H§9 CLI 子指令 | 18 | 3 | 12 | 3 | 36 |
| H§20 Profile／設定／秘密 | 5 | 1 | 3 | 0 | 9 |
| H§21 批次／評測 | 0 | 1 | 4 | 1 | 6 |
| H§22 桌面／TUI／Web | 3 | 1 | 5 | 1 | 10 |
| O§5 Chat/slash | 22 | 6 | 7 | 1 | 36 |
| O§6 CLI | 22 | 7 | 9 | 4 | 42 |
| O§10 Control UI | 3 | 7 | 17 | 0 | 27 |
| O§11 Ops | 10 | 6 | 11 | 1 | 28 |

**頻道斜線派送**：有。`crates/ark/src/ext.rs:876-893`（`Action::Submit` 內 `text.starts_with('/')` → `slash::run(&slash_ctx(..))`，回覆文字、`NewSession` 重設路由、`prompt` 轉為回合），存取控制 `ext.rs:957 sender_access`＋`slash.rs:227 allowed`（admin／`user_allowed_commands`；`local` 指令在頻道被擋）。測試 `slash.rs::channel_access_and_local_commands`。原生選單：`ext.rs:655` 由 `slash::defs()` 組 menu → `ark_channel::set_menu`，Telegram `setMyCommands`／Discord application commands（`ark-channel/src/lib.rs telegram_menu/discord_menu`，測試 `menu_tests::native_menus_follow_platform_rules`）；Slack 由 `ark slack manifest`。`ark chat` REPL（`main.rs chat_slash`）與 TUI（`tui.rs:457` 經 daemon `command.run` → `slash::methods`）共用同一張表。**缺口**：TUI 只顯示 `text`／`prompt`，忽略 `action`（`/new`、`/clear`、`/quit`、`/redraw`、`/copy`… 在 TUI 無效果）；web UI 完全沒有斜線輸入。

## Hermes §8 斜線指令（本流 59 列）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| /start | hermes_cli/commands.py (H§8) | N/A | 平台 start ping，channel 層 |
| /new (/reset) | commands.py (H§8) | ✅ | `slash.rs` def `new`→`Action::NewSession`；chat/頻道處理；`config_tools_personality_display`（/clear 同路徑） |
| /topic | commands.py (H§8) | N/A | Telegram DM topic，channel 層 |
| /clear | commands.py (H§8) | ✅ | def `clear`→`NewSession{clear:true}`，`main.rs chat_slash` 清畫面；測試 `config_tools_personality_display` |
| /redraw | commands.py (H§8) | ✅ | `Action::Local("redraw")`，chat 重繪＋/history 40；測試同上（TUI 忽略） |
| /history | commands.py (H§8) | ✅ | `cmd_history`；`session_commands_status_history_save_title` |
| /save | commands.py (H§8) | ✅ | `cmd_save` md/html/json/jsonl/trajectory；同上測試 |
| /prompt (/compose) | commands.py (H§8) | 🚧 | `Local("compose")`→`ark_app::clip::compose`（$EDITOR），僅 `ark chat`；compose 無測試，TUI/web 無 |
| /title | commands.py (H§8) | ✅ | `cmd_title`（別名 /name）；`session_commands_status_history_save_title` |
| /worktree | commands.py (H§8) | ⬜ | 無 |
| /snapshot (/snap) | commands.py (H§8) | ✅ | `ops/slashops.rs`→`backup::snapshot_command`；`backup.rs::snapshots` |
| /export | commands.py (H§8) | ✅ | `slashops cmd_export`→`profile::export`；`profile.rs::lifecycle_clone_export_import` |
| /import | commands.py (H§8) | ✅ | `slashops cmd_import`→`profile::import`；同上 |
| /discard | commands.py (H§8) | ✅ | `cmd_discard`；`queue_discard_and_busy` |
| /btw | commands.py (H§8) | ✅ | `cmd_btw`/`side_answer`（無工具、不寫入）；`btw_leaves_the_conversation_alone` |
| /queue (/q) | commands.py (H§8) | ✅ | `cmd_queue` list/rm/edit/move/clear/mode/cap＋`ark-kernel/src/queue.rs`；`queue_discard_and_busy`、`queue.rs::modes_caps_and_release` |
| /steer (/s) | commands.py (H§8) | ✅ | `cmd_steer`（Mode::Steer）；kernel 測試 `runner.rs::queue_modes_followup_interrupt_and_edit`（cmd 本身無直接測試） |
| /review | commands.py (H§8) | ✅ | `cmd_review` 子 session 審查並回注；`review_runs_a_child_and_reports_back` |
| /plan | commands.py (H§8) | ✅ | `plan_prompt` 寫 `.ark/plans/`；`prompt_commands` |
| /status | commands.py (H§8) | ✅ | `cmd_status`（含 queue、context %）；`session_commands_status_history_save_title` |
| /context (/ctx) | commands.py (H§8) | ✅ | `context_report` 分類儀表；同上測試 |
| /whoami | commands.py (H§8) | ✅ | `cmd_whoami`（原 N/A，現實作 admin/user tier）；`channel_access_and_local_commands` |
| /profile | commands.py (H§8) | ✅ | `slashops cmd_profile`→`profile::current`；profile 測試（slash 包裝本身無測試） |
| /sethome | commands.py (H§8) | N/A | 家頻道，channel 層 |
| /config | commands.py (H§8) | ✅ | `cmd_config` show/get/set/unset（admin、redact）；`config_tools_personality_display` |
| /personality | commands.py (H§8) | ✅ | `cmd_personality`、`personalities()`；同上 |
| /statusbar (/sb) | commands.py (H§8) | 🚧 | 回 `Local("statusbar")`；`ark chat` 只印「lives in ark tui」，TUI 忽略 action、無狀態列 |
| /battery | commands.py (H§8) | ⬜ | 無 |
| /timestamps (/ts) | commands.py (H§8) | 🚧 | 存入 `display.json`，只套用於 `/history`（`slash.rs:348`）；即時訊息不顯示 |
| /diff | commands.py (H§8) | ✅ | `cmd_diff`（含 untracked）；`diff_and_manifest` |
| /verbose | commands.py (H§8) | 🚧 | 只在頻道套用（`ext.rs:1054`）；`ark chat`/TUI 不讀 |
| /focus | commands.py (H§8) | 🚧 | 只寫 `display.json`，沒有任何消費端 |
| /footer | commands.py (H§8) | ✅ | 頻道回覆附資訊 `ext.rs:1082`；設定測試 `config_tools_personality_display`（套用路徑無測試） |
| /busy | commands.py (H§8) | ✅ | `cmd_busy` 存 `runner.busy_mode`；`queue_discard_and_busy` |
| /tools | commands.py (H§8) | ✅ | `tools_command` list/enable/disable/@toolset；`config_tools_personality_display` |
| /toolsets | commands.py (H§8) | ✅ | `toolsets()`；同上 |
| /skin | commands.py (H§8) | ⬜ | 無主題切換 |
| /indicator | commands.py (H§8) | ⬜ | 無 |
| /pet | commands.py (H§8) | ⬜ | 無 |
| /hatch | commands.py (H§8) | ⬜ | 無 |
| /learn | commands.py (H§8) | ✅ | `learn_prompt`；`prompt_commands` |
| /init | commands.py (H§8) | ✅ | `init_prompt`（含 MERGE DISCIPLINE）；`prompt_commands` |
| /reload | commands.py (H§8) | ✅ | `slashops`→`envfile::reload`；`envfile.rs::process_env_wins_and_reload_updates_ours` |
| /reload-mcp | commands.py (H§8) | ✅ | 既有，未改動：`ark mcp refresh`；無斜線版 |
| /commands | commands.py (H§8) | ✅ | `cmd_commands`；`diff_and_manifest`（command_list） |
| /help | commands.py (H§8) | ✅ | `help_text`；`parse_find_and_help` |
| /palette | commands.py (H§8) | 🚧 | 只有 `command.list` ARP（`slash.rs:1371`）；TUI/web 無模糊面板 |
| /restart | commands.py (H§8) | 🚧 | CLI `ark service restart --drain` 有；`service::restart_detached` 寫了但**無呼叫者**、無 /restart 斜線，`/activation`、`/allowlist` 回覆卻提示使用者「/restart」 |
| /subscription (/upgrade) | commands.py (H§8) | N/A | Nous 帳務 |
| /topup | commands.py (H§8) | N/A | Nous 帳務 |
| /platforms (/gateway) | commands.py (H§8) | 🚧 | `cmd_platforms` 已接線；無測試 |
| /platform | commands.py (H§8) | N/A | channel 層 |
| /copy | commands.py (H§8) | ✅ | `Local("copy")`→`ark_app::clip::copy`（OSC52/xclip…）；`clip.rs::clipboard_tools_from_path` |
| /paste | commands.py (H§8) | ✅ | `clip::paste_image` 附到下一則；同上測試（僅 ark chat） |
| /update | commands.py (H§8) | 🚧 | 斜線只做 `update::check_text` 檢查，不執行更新 |
| /version | commands.py (H§8) | ✅ | def `version`；`parse_find_and_help` |
| /debug | commands.py (H§8) | ⬜ | 無除錯報告上傳／dump |
| /quit (/exit) | commands.py (H§8) | ✅ | `Action::Quit{delete}`（--delete 刪 session）；`config_tools_personality_display` |
| Ctrl+S prompt 暫存 | hermes_cli/prompt_stash.py (H§8) | ⬜ | 無 |

## Hermes §9 CLI 子指令（本流 36 列）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| chat（-q/-Q/-z/stream-json） | _parser.py, oneshot.py (H§9) | ✅ | 既有，未改動（chat REPL 斜線改接 `chat_slash`） |
| setup | subcommands/setup.py (H§9) | ✅ | 既有，未改動（`setup.rs`） |
| config show/edit/get/set/unset/path/env-path/check/migrate | subcommands/config.py (H§9) | ✅ | `ops/confcli.rs` set/unset/patch/edit/file/env-path/schema/check/migrate/backups/restore；`set_unset_keep_comments_and_validate`、`patch_schema_and_migrations` |
| gateway run/start/stop/restart/status/install… | subcommands/gateway.py (H§9) | ✅ | 既有＋`ops/service.rs` restart --drain/logs/audit；`units_plist_and_audit` |
| status | subcommands/status.py (H§9) | 🚧 | `ops/status.rs` 為空殼；只有既有 `ark daemon status`/`ark health` |
| doctor | subcommands/doctor.py (H§9) | ✅ | 既有，未改動（`main.rs cmd_doctor`）；`ops/doctor.rs` 空殼，無修復（見 O§11） |
| dump | subcommands/dump.py (H§9) | ⬜ | 無 |
| debug share/delete | subcommands/debug.py (H§9) | ⬜ | 無 |
| logs | subcommands/logs.py (H§9) | ✅ | `ops/logs.rs` 檔案日誌（輪替、--level/--since/--grep/--follow/--json），daemon `logs::install`（`main.rs:956`）；`writes_rotates_and_filters` |
| tools list/disable/enable/post-setup | subcommands/tools.py (H§9) | 🚧 | `ark tools`（`slash::tools_command`）全域開關；無每平台設定、無 post-setup |
| mcp | subcommands/mcp.py (H§9) | ✅ | 既有，未改動 |
| profile（list/use/create/delete/describe/show/alias/rename/export/import/install/update） | subcommands/profile.py (H§9) | ✅ | `ops/profile.rs` 全部子指令＋`-p/--profile/ARK_PROFILE` early；`lifecycle_clone_export_import`、`distribution_install_and_alias` |
| project | projects_cmd.py (H§9) | ⬜ | 無 |
| secrets bitwarden/onepassword | subcommands/secrets.py, agent/secret_sources (H§9) | ⬜ | `ops/secretsrc.rs` 空殼；無 Bitwarden/1Password/command 來源 |
| pairing | subcommands/pairing.py (H§9) | ✅ | 既有，未改動 |
| prompt-size | subcommands/prompt_size.py (H§9) | ✅ | `ark prompt-size`（`slash::dispatch`，--json）；`context_report` 經 `session_commands_…` 測試 |
| backup / import | backup*.py (H§9) | ✅ | `ops/backup.rs` create/verify/restore/list/prune/schedule＋`archive.rs` tar/deflate；`create_verify_restore`、`tar_roundtrip_long_names_and_traversal` |
| worktree list/prune/restore | worktree_cmd.py (H§9) | ⬜ | 無 |
| update / uninstall | update_cmd*.py, uninstall.py (H§9) | ✅ | `ops/update.rs` 頻道 stable/beta/dev、sha256 驗證、`ark.prev`/--rollback、uninstall --purge；`fetch_verifies_checksums_against_a_fake_release_server`、`versions_and_channels`（uninstall 無測試；無 fleet） |
| completion | subcommands/completion.py (H§9) | ✅ | `ops/completion.rs` bash/zsh/fish/install；`scripts_cover_the_tree` |
| console | console_engine.py (H§9) | ⬜ | 無 |
| dashboard serve/register | main_dashboard.py (H§9) | ✅ | 既有，未改動（`ark app`） |
| gui / desktop | main_desktop.py (H§9) | N/A | Hermes Electron |
| acp | subcommands/acp.py (H§9) | ✅ | 既有，未改動 |
| import-agent | agent_import*.py (H§9) | ✅ | `ops/migrate.rs` `import-agent`/`migrate from claude|codex|hermes`；`hermes_claude_codex_import` |
| claw migrate/cleanup | claw.py (H§9) | ✅ | `migrate.rs` `claw migrate`/`cleanup`；`openclaw_import`（cleanup 無測試） |
| connectors | connectors_cmd.py (H§9) | ⬜ | 無 |
| monitoring status（OTLP） | subcommands/monitoring.py (H§9) | 🚧 | `TelemetryConfig`（config.rs）已加，`ops/telemetry.rs` 空殼：無任何 OTLP 匯出器、無 `ark telemetry` 指令；LangSmith OTel 相容性無從驗證 |
| pets | pets.py (H§9) | ⬜ | 無 |
| skin list/use/set | skin_engine.py (H§9) | ⬜ | 無 |
| slack manifest | slack_cli.py (H§9) | ✅ | `ark slack manifest`（`slash::slack_manifest`）；`diff_and_manifest` |
| whatsapp | subcommands/whatsapp.py (H§9) | N/A | channel 層 |
| verify | verify_cmd.py (H§9) | ⬜ | 無 |
| lsp | agent/lsp/cli.py (H§9) | ⬜ | 無 |
| portal / proxy | portal_cli.py (H§9) | N/A | Nous 服務 |
| gateway multiplex | gateway_multiplex*.py (H§9) | ⬜ | 一行程多 profile 無 |

## Hermes §20 Profile／設定／秘密（9 列）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| Profiles（多隔離實例） | hermes_cli/profiles*.py (H§20) | ✅ | `ops/profile.rs`（`early` 切換 ARK_HOME、sticky `profile use`、clone/export/import/install）；profile 兩個測試 |
| 分層設定 | config*.py (H§20) | ✅ | 既有，未改動 |
| 設定遷移與備份 | config_migrations.py, config_backups.py (H§20) | ✅ | `confcli` `config migrate`（`config_version`）、`config backups/restore`；`patch_schema_and_migrations` |
| .env 載入 | env_loader.py (H§20) | ✅ | `ops/envfile.rs` `early()`（main 起點）＋`/reload`；`parses_dotenv_syntax`、`process_env_wins_and_reload_updates_ours` |
| 本機秘密庫 | secrets_cli.py (H§20) | ✅ | 既有，未改動 |
| 外部秘密來源 Bitwarden/1Password/command | agent/secret_sources/* (H§20) | ⬜ | `ops/secretsrc.rs` 空殼 |
| 首次 onboarding | agent/onboarding*.py (H§20) | 🚧 | 既有 `ark setup`；`setup.rs` 未改動，無情境提示 |
| 啟動提示 tips | tips.py (H§20) | ⬜ | 無 |
| 終端通知 OSC 9/777 | terminal_notify.py (H§20) | ⬜ | 無（grep 無 `]9;`/`]777;`） |

## Hermes §21 批次／評測（6 列）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| batch_runner | batch_runner.py (H§21) | ⬜ | `ops/batch.rs` 空殼（`COMMANDS=&[]`） |
| mini_swe_runner | mini_swe_runner.py (H§21) | ⬜ | 無 |
| trajectory_compressor | trajectory_compressor.py (H§21) | ⬜ | 無（`/save trajectory` 只匯出 ShareGPT 格式，不壓縮） |
| toolset_distributions | toolset_distributions.py (H§21) | ⬜ | 無 |
| evals/ | evals/* (H§21) | 🚧 | `ops/evals.rs` 空殼；只有既有整合測試 |
| RL（`hermes rl`） | main.py (H§21) | N/A | 上游未實作 |

## Hermes §22 桌面／TUI／Web（本流 10 列）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| Electron 桌面 app | apps/desktop (H§22) | N/A | Hermes 桌面 |
| TUI（ui-tui＋tui_gateway） | ui-tui (H§22) | ✅ | 既有，未改動；`tui.rs:457` 經 `command.run` 用共用斜線表，但**不處理 action** |
| 經典 CLI live dock | cli_subagent_monitor.py (H§22) | ⬜ | 無 |
| 狀態列（git 分支、電量、context） | cli_status_bar_mixin.py (H§22) | ⬜ | 無（/statusbar 無效果） |
| Web 儀表板 | web/, web_server*.py (H§22) | 🚧 | `ui/web` 未改動；無設定/cron/記憶/檔案頁 |
| OpenAI 相容 API server | gateway (H§22) | ✅ | 既有，未改動 |
| mcp_serve 對話工具 | mcp_serve.py (H§22) | ✅ | 既有，未改動 |
| Hosted rooms / 群組聊天 | tui_gateway/hosted_room_*.py (H§22) | ⬜ | 無 |
| Petdex 寵物 | agent/pet (H§22) | ⬜ | 無 |
| Skins | skin_engine.py (H§22) | ⬜ | 無 |

## OpenClaw §5 Chat/slash（本流 36 列）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| /help | commands-registry.shared.ts (O§5) | ✅ | `help_text`（依權限隱藏）；`parse_find_and_help`、`channel_access_and_local_commands` |
| /commands | 同上 (O§5) | ✅ | `cmd_commands`、`command_list`；`diff_and_manifest` |
| /tools | 同上 (O§5) | ✅ | `cmd_tools`；`config_tools_personality_display` |
| /dashboard | 同上 (O§5) | ⬜ | 無 |
| /learn | 同上 (O§5) | ✅ | `learn_prompt`；`prompt_commands` |
| /status | 同上 (O§5) | ✅ | `cmd_status`；`session_commands_…` |
| /diagnostics | 同上 (O§5) | ⬜ | 無 |
| /openclaw（setup/repair helper） | 同上 (O§5) | ⬜ | 無 |
| /allowlist | 同上 (O§5) | 🚧 | `cmd_allowlist` 寫 `channels.<ch>.allow`；無測試，需重啟 daemon 才生效（且 /restart 不存在） |
| /context | 同上 (O§5) | ✅ | `context_report`；`session_commands_…` |
| /btw (/side) | 同上 (O§5) | ✅ | `cmd_btw`；`btw_leaves_the_conversation_alone` |
| /export-session | 同上 (O§5) | ✅ | HTML 自包含無 script；`session_commands_…` |
| /export-trajectory | 同上 (O§5) | ✅ | `trajectory()` JSONL；`session_commands_…` |
| /whoami (/id) | 同上 (O§5) | ✅ | `cmd_whoami`；`channel_access_and_local_commands` |
| /steer (/tell) | 同上 (O§5) | ✅ | `cmd_steer`；kernel `queue_modes_followup_interrupt_and_edit` |
| /followup | 同上 (O§5) | ✅ | `followup()`（Mode::Followup）；同上 kernel 測試 |
| /config show/get/set/unset | 同上 (O§5) | ✅ | `cmd_config`；`config_tools_personality_display` |
| /mcp show/get/set/unset | 同上 (O§5) | ✅ | `cmd_mcp`；同上 |
| /debug | 同上 (O§5) | ⬜ | 無 runtime debug overrides |
| /stop | 同上 (O§5) | ✅ | `k.interrupt`；既有頻道 /stop 改走共用表 |
| /restart | 同上 (O§5) | ⬜ | 無斜線（`restart_detached` 未接線） |
| /update | 同上 (O§5) | 🚧 | 只檢查版本，不更新／重啟 |
| /activation mention/always | 同上 (O§5) | 🚧 | `cmd_activation` 寫 `require_mention`；無測試、需重啟 |
| /send on/off/inherit | 同上 (O§5) | 🚧 | `cmd_send`＋`ext.rs:1076` 套用；無測試 |
| /reset | 同上 (O§5) | ✅ | `new` 別名 |
| /new | 同上 (O§5) | ✅ | 同 H§8 |
| /name | 同上 (O§5) | ✅ | `title` 別名；`session_commands_…` 測 `/name` |
| /verbose (/v) | 同上 (O§5) | 🚧 | 僅頻道套用；`/v` 別名被 `version` 占用 |
| /trace | 同上 (O§5) | 🚧 | 只寫 `display.json`，無消費端 |
| /queue | 同上 (O§5) | ✅ | `cmd_queue mode steer/followup/collect/interrupt`；`queue_discard_and_busy` |
| /forget | ark 額外 (O§5) | ✅ | 既有，未改動 |
| /pair | extensions/device-pair (O§5) | ⬜ | 無 |
| /controlui (miniapp) | extensions/telegram/src/miniapp (O§5) | ⬜ | 無 |
| /reef | extensions/reef (O§5) | N/A | 特定 channel 指令 |
| Custom markdown commands | chat-command-invocation.ts (O§5) | ✅ | 既有，未改動（`ark-kernel/commands.rs`） |
| Native command menus | channel plugins (O§5) | ✅ | `ext.rs:655 set_menu`、Telegram/Discord 選單；`native_menus_follow_platform_rules`；Slack manifest |

## OpenClaw §6 CLI（本流 42 列）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| onboard / setup | register.onboard.ts (O§6) | 🚧 | 既有 `ark setup`，未改動；缺 O§11 各步 |
| configure | register.configure.ts (O§6) | 🚧 | `confcli::configure` 互動式分節已接線；無測試 |
| config get/set/patch/unset/file/schema/validate | config-cli*.ts (O§6) | ✅ | `ops/confcli.rs`；三個測試 |
| backup create/verify/restore | register.backup.ts (O§6) | ✅ | `ops/backup.rs`；`create_verify_restore` |
| database | register.database.ts (O§6) | N/A | Node SQLite 基礎設施 |
| migrate | register.migrate.ts (O§6) | ✅ | `ops/migrate.rs`（openclaw/hermes/claude/codex，dry-run 計畫）；`openclaw_import` 等 |
| storage | register.storage.ts (O§6) | ⬜ | 無 |
| doctor | src/flows/doctor-* (O§6) | 🚧 | 既有檢查；`ops/doctor.rs` 空殼，無 repair |
| triage | core-command-descriptors.ts (O§6) | ⬜ | 無 |
| dashboard | 同上 (O§6) | ✅ | 既有，未改動 |
| reset | 同上 (O§6) | ✅ | `update.rs reset --scope`（先備份）；`reset_scopes` |
| uninstall | 同上 (O§6) | 🚧 | `update.rs uninstall --purge/--remove-binary` 已實作；無測試 |
| mcp | mcp-cli.ts (O§6) | ✅ | 既有，未改動 |
| agent | register.agent-turn.ts (O§6) | ✅ | 既有，未改動（`ark run`） |
| status | register.status-health-sessions.ts (O§6) | 🚧 | `ops/status.rs` 空殼 |
| health | 同上 (O§6) | ✅ | 既有，未改動 |
| audit | register.audit.ts (O§6) | ⬜ | 無 |
| acp | acp-cli.ts (O§6) | ✅ | 既有，未改動 |
| gateway run/status | gateway-cli (O§6) | ✅ | 既有，未改動 |
| daemon install（launchd/systemd/schtasks） | daemon-cli (O§6) | ✅ | `ops/service.rs` systemd user/system、launchd plist（`--launchd`）、schtasks 明列 N/A；`units_plist_and_audit` |
| logs | logs-cli.ts (O§6) | ✅ | `ops/logs.rs`；`writes_rotates_and_filters` |
| telemetry | telemetry-cli.ts (O§6) | N/A | 匿名遙測控制，ark 無匿名遙測 |
| nodes | nodes-cli (O§6) | ✅ | 既有，未改動 |
| devices | devices-cli.ts (O§6) | ✅ | 既有，未改動 |
| users | users-cli.ts (O§6) | ⬜ | 無 |
| node / connect | node-cli (O§6) | ✅ | 既有，未改動 |
| worker | worker-cli.ts (O§6) | ⬜ | 無 |
| worktrees | worktrees-cli.ts (O§6) | ⬜ | 無 |
| attach | attach-cli.ts (O§6) | 🚧 | 既有，未改動 |
| tui / chat / resume | tui-cli.ts (O§6) | ✅ | 既有，未改動 |
| dns | dns-cli.ts (O§6) | ⬜ | 無 |
| qa | qa-lab (O§6) | N/A | 開發用 |
| proxy | proxy-cli.ts (O§6) | ⬜ | 無 |
| qr | qr-cli.ts (O§6) | ✅ | 既有，未改動 |
| clawbot | clawbot-cli.ts (O§6) | N/A | 舊別名 |
| pairing | pairing-cli.ts (O§6) | ✅ | 既有，未改動 |
| channels | channels-cli.ts (O§6) | 🚧 | 既有 `ark channel list/send`，未改動 |
| directory | directory-cli.ts (O§6) | ⬜ | 無 |
| secrets | secrets-cli.ts (O§6) | ✅ | 既有，未改動（外部 store 見 H§20 ⬜） |
| update | update-cli (O§6) | ✅ | `ops/update.rs`；`fetch_verifies_checksums_against_a_fake_release_server` |
| completion | completion-cli.ts (O§6) | ✅ | `ops/completion.rs`；`scripts_cover_the_tree` |
| data export/delete | ark 額外 (O§6) | ✅ | 既有，未改動 |

## OpenClaw §10 Control UI（本流 27 列；`ui/web` 全未改動）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| Chat | ui/src/pages/chat (O§10) | 🚧 | 既有；無附件/工具卡/斜線 |
| Sessions / new-session | pages/sessions (O§10) | ✅ | 既有，未改動 |
| Approvals / question | pages/approvals (O§10) | ✅ | 既有，未改動 |
| Model providers / model-setup | pages/model-providers (O§10) | 🚧 | 既有唯讀 |
| Channels | pages/channels (O§10) | ⬜ | 無頁面 |
| Devices | pages/devices (O§10) | 🚧 | 既有唯讀 |
| Plugins | pages/plugins (O§10) | 🚧 | 既有 |
| Skills / skill-workshop | pages/skills (O§10) | ⬜ | 無 |
| Cron | pages/cron (O§10) | ⬜ | 無 |
| Usage | pages/usage (O§10) | ⬜ | 無 |
| Config | pages/config (O§10) | ⬜ | 無頁面、無 config ARP（`ui_methods` 空殼） |
| Logs / debug / activity | pages/logs (O§10) | 🚧 | 後端 `logs.tail` ARP 有（`logs::methods`），前端無頁面 |
| Secrets | pages/secrets (O§10) | ⬜ | 無 |
| Terminal | pages/terminal (O§10) | ⬜ | 無 |
| Dashboards / apps / portals | pages/dashboards (O§10) | ⬜ | 無 |
| Workboard | pages/workboard (O§10) | ⬜ | 無 |
| Agents | pages/agents (O§10) | ⬜ | 無 |
| Claws / lobsterdex | pages/claws (O§10) | ⬜ | 無 |
| Memory import | pages/memory-import (O§10) | ⬜ | 無 |
| Meetings | pages/meetings (O§10) | ⬜ | 無 |
| Worktrees | pages/worktrees (O§10) | ⬜ | 無 |
| Cloud workers | pages/cloud-workers (O§10) | ⬜ | 無 |
| Search | pages/search (O§10) | ⬜ | 無 |
| Systems / custodian / labs / about / profile | pages/* (O§10) | ⬜ | 無 |
| i18n | ui/src/i18n (O§10) | 🚧 | 既有，web 單語 |
| Themes | ui/src/assets/themes (O§10) | 🚧 | 既有單一主題 |
| PWA install | — (O§10) | ✅ | 既有，未改動 |

## OpenClaw §11 Ops（本流 28 列）

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| Wizard: security note | setup.security-note.ts (O§11) | ⬜ | `setup.rs` 未改動 |
| Wizard: migration import | setup.migration-*.ts (O§11) | ⬜ | `ark migrate` CLI 有，精靈未呼叫 |
| Wizard: model auth | setup.model-auth.ts (O§11) | 🚧 | 既有，只有 API key |
| Wizard: inference verification | setup.inference-verification.ts (O§11) | ✅ | 既有，未改動 |
| Wizard: workspace | setup.workspace.ts (O§11) | ⬜ | 無 |
| Wizard: gateway config + auth | setup.gateway-config.ts (O§11) | 🚧 | 既有 |
| Wizard: service runtime install | setup.service-runtime.ts (O§11) | ⬜ | `ark service install` 有，精靈未呼叫 |
| Wizard: official plugins | setup.official-plugins.ts (O§11) | ⬜ | 無 |
| Wizard: channel setup | channel-setup*.ts (O§11) | 🚧 | 既有，僅 3 種 |
| Wizard: app recommendations / completion | setup.completion.ts (O§11) | ⬜ | `ark completion install` 有，精靈未提供 |
| Wizard i18n | src/wizard/i18n (O§11) | ✅ | 既有，未改動 |
| Service: systemd | src/daemon/systemd* (O§11) | ✅ | `ops/service.rs`（user/system unit）；`units_plist_and_audit` |
| Service: launchd | launchd*.ts (O§11) | ✅ | plist 產生＋`launchctl load`（僅 macOS 實跑）；`units_plist_and_audit` |
| Service: schtasks | schtasks*.ts (O§11) | N/A | ark 無 Windows build（unix socket、POSIX signal），`service.rs:7` 註明 |
| Restart-storm / service audit | restart-storm.ts, service-audit*.ts (O§11) | ✅ | `record_start`（daemon 啟動 `main.rs:935`）、`audit_text`、`ark service audit`；`restart_storm_detection`、`units_plist_and_audit`（未併入 doctor） |
| Doctor: config validation | doctor-config-validation (O§11) | ✅ | 既有，未改動 |
| Doctor: auth health | doctor-auth-health.ts (O§11) | ✅ | 既有，未改動 |
| Doctor: gateway auth/services/exec credential | doctor-gateway-* (O§11) | 🚧 | 既有 ping；service audit 未接進 doctor |
| Doctor: model reference check | doctor-model-reference-check.ts (O§11) | 🚧 | 既有 `ark providers check` |
| Doctor: tool schema check | doctor-tool-schema-* (O§11) | ⬜ | 無 |
| Doctor: channel/native/workspace/removed-state | doctor-* (O§11) | ⬜ | 無 |
| Doctor: repair flow / lint flow | doctor-repair-flow.ts (O§11) | ⬜ | `ops/doctor.rs` 空殼，無 `--fix`/repair |
| Update mechanism | update-cli, infra/update* (O§11) | ✅ | `ops/update.rs`（channels、checksum、rollback、停 daemon 後替換）；fake release server 測試 |
| Backup + retention | infra/backup-*.ts (O§11) | ✅ | `backup::spawn_scheduler`（daemon `main.rs:947`）、retention；`retention_buckets` |
| Logs (file logs, RPC tail) | src/logging, logs-cli.ts (O§11) | ✅ | `ops/logs.rs` writer tap＋`logs.tail` ARP；`writes_rotates_and_filters` |
| Canvas host | src/canvas (O§11) | ⬜ | 無 |
| Telegram mini-app Control UI | telegram/src/miniapp (O§11) | ⬜ | 無 |
| Docker / compose / fly / render | Dockerfile… (O§11) | 🚧 | 既有，未改動 |

## 不屬本流的列

（不判定、不計入；共 131 列）

- **models**：H§8 /model /codex-runtime /reasoning /fast /usage /login /insights；H§9 model, auth, login/logout, fallback, insights, usage, migrate xai/relay, codex-runtime migrate；O§5 /login /usage /think /fast /reasoning /model /models；O§6 models, promos
- **agents**：H§8 /retry /undo /handoff /branch /rollback /bg /agents /moa /resume /sessions /autoprune；H§9 moa, sessions, resume, peer, checkpoints；O§5 /session /subagents /acp /agents /undo /codex；O§6 transcripts, agents, sessions, checkpoint
- **skills**：H§8 /compress /journey /refine /skills /memory /bundles /curator /reload-skills /plugins /<skill-name> /<bundle-name> 外掛斜線；H§9 skills, bundles, curator, memory, journey, plugins；H§22 學習星圖/journey；O§5 /skill /plugins /compact /active-memory /dreaming；O§6 claws, plugins, skills；O§11 Wizard memory setup
- **automation**：H§8 /goal /heartbeat /loop /subgoal /cron /suggestions /blueprint /kanban；H§9 cron, hooks, webhook, send；O§5 /loop /goal /workboard；O§6 message, system, cron, hooks, webhooks
- **exec**：H§8 /stop（殺背景行程）/egress、`!cmd`；H§9 egress；O§5 /exec /bash；O§6 sandbox
- **security**：H§8 /pause /approve /deny /yolo /approvals；H§9 security audit；O§5 /approve /elevated；O§6 approvals, exec-policy, security
- **browser**：H§8 /browser；H§9 vault, computer-use, screen, browser close-profile；O§10 Browser/desktop view；O§11 Doctor browser permissions
- **media**：H§8 /voice /wake /image；O§5 /tts /voice；O§6 infer/capability
- **web**：O§6 docs；O§11 Wizard web search setup

## 剩餘缺口（依使用者影響排序）

1. OpenTelemetry 匯出（H§9 monitoring）：只有 `TelemetryConfig`，`ops/telemetry.rs` 空殼，無 OTLP traces/metrics/logs 匯出、無指令；LangSmith OTel 相容性無程式可判。
2. 外部秘密來源（H§20、H§9 secrets bitwarden/onepassword）：`ops/secretsrc.rs` 空殼，無 Bitwarden/1Password/command。
3. Doctor 修復流程（O§11 repair/lint、O§6 doctor）：`ops/doctor.rs` 空殼；無 `--fix`、未併入 service audit、無 tool-schema／channel／workspace 檢查（O§11 三列）。
4. Web UI 頁面（O§10 17 ⬜＋H§22 Web 儀表板）：`ui/web` 未改動；Config/Channels/Cron/Usage/Secrets/Terminal/Dashboards/Skills 等頁面全無，`ui_methods.rs` 空殼；Logs 只有後端 `logs.tail`。
5. Batch runner／evals（H§21）：`ops/batch.rs`、`ops/evals.rs` 空殼；mini_swe_runner、trajectory_compressor、toolset_distributions 皆無。
6. /restart（H§8 🚧、O§5 ⬜）：`service::restart_detached` 已寫但無呼叫者，無斜線；/activation、/allowlist 卻要使用者「/restart」。
7. `ark status`（H§9、O§6）：`ops/status.rs` 空殼，無全元件狀態彙整。
8. TUI 斜線 action（H§22 TUI、H§8 /statusbar /redraw…）：TUI 忽略 `action`，/new /clear /quit /copy 等在 TUI 無效；無狀態列（H§22 ⬜、/statusbar 🚧）、無指令面板（/palette 🚧）、無 live dock（⬜）。
9. 顯示偏好未套用：/verbose 只在頻道、/timestamps 只在 /history、/focus 與 /trace 無消費端（H§8、O§5）。
10. 精靈步驟（O§11）：security note、migration import、workspace、service install、official plugins、completion 推薦皆未進 `ark setup`；model auth 只有 API key、gateway/channel 部分；H§20 onboarding 情境提示無。
11. /update 斜線只檢查（H§8、O§5）；O§6 uninstall、configure 無測試；/allowlist、/activation、/send、/platforms 無測試（O§5、H§8）。
12. `ark tools` 無每平台開關／post-setup（H§9）。
13. /prompt (/compose) 只在 `ark chat`，compose 無測試（H§8）。
14. /debug、dump、debug share（H§8、H§9、O§5 /debug）：無除錯報告。
15. /diagnostics、/openclaw、/dashboard、/pair、/controlui（O§5）：無。
16. worktree（H§8 /worktree、H§9 worktree、O§6 worktrees）：無。
17. CLI 其他 ⬜：project、console、connectors、verify、lsp、gateway multiplex（H§9）；storage、triage、audit、users、worker、dns、proxy、directory（O§6）。
18. O§6 onboard、attach、channels、O§10 Chat/Model providers/Devices/Plugins/i18n/Themes、O§11 model reference/gateway checks/Docker：既有 🚧，本輪未改。
19. Skins／主題、寵物、電量、indicator、prompt stash（H§8 /skin /pet /hatch /battery /indicator、Ctrl+S；H§9 pets/skin；H§22 Petdex/Skins）：無。
20. Hosted rooms（H§22）、tips、OSC 9/777 通知（H§20）、Canvas host、Telegram mini-app（O§11）：無。
