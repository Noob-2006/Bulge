# exec 串流稽核結果

**編譯／測試**：`cargo build --workspace --all-targets` 成功；`cargo test --workspace --no-fail-fast` 通過 839、失敗 3、忽略 2。
- 失敗：`seagent_tools::exec::local::tests::bwrap_hides_home_and_blocks_network`（`only the header line: no routes without network: inside1`），也就是 bwrap 沙箱內**仍看得到網路路由**，網路隔離**沒有生效**。這是本串流的真實缺陷，或至少在此機器上不成立。
- coderun 兩個測試（`coderun::tests::script_output_exit_codes_and_nested_protocol`、`failures_timeout_cancel_and_bad_lang`）在五個副本都失敗，原因是稽核規定的 TMPDIR 路徑過長，Unix socket 超過 SUN_LEN（`cannot bind …/call-*.sock: path must be shorter than SUN_LEN`）。這是環境造成的，與本串流程式無關。
- 原始輸出：`audit/exec-tests.txt`

**狀態統計（62 列）**：✅ 17 · 🚧 29 · ⬜ 15 · N/A 1


# exec 串流稽核（w-exec，基於 5c369e5 + 未提交工作）

## 差異範圍

`git diff --stat HEAD`：33 檔、+11661/−140。另有未追蹤 `crates/seagent-tools/src/exec/ansi.rs`、`crates/seagent-tools/src/tokenjuice/json.rs`。

- 新增且已接上：`seagent-tools/src/{fuzzy,patchfmt,extract,zip,filestate,lint}.rs`，經 `fs.rs`（read/write/edit/patch/新工具 `apply_patch`）與 `search.rs`（grep/glob 新參數）使用；`seagent-core/src/tool.rs` 圖片標記 + `seagent-kernel/src/kernel.rs` 把 `read` 的圖片轉成 `Block::Image`；`seagent-app/src/acp.rs` 把 `apply_patch` 視為 edit。
- 新增但**未接上**：整個 `seagent-tools/src/exec/`（`ExecEnv`、`ExecConfig`、local/bwrap/landlock、sandbox 政策、sync、modal/daytona/vercel）與 `seagent-core/src/exec.rs`（`ExecBackend` trait、`install_selector`/`backend_for`）。`shell.rs`、`job.rs`、`seagent-kernel/src/coderun.rs` 完全未改（`git status` 無 M），仍直接 `Command::new("bash")`；全 repo 沒有任何地方呼叫 `exec::install`、`exec::global`、`ExecConfig::parse`、`install_selector`、`backend_for`、`sandbox::wrap_all`、`configure_files`。`config.rs`、`main.rs` 未改，故 `[exec]`、`[files]` 設定使用者無法設定。
- **stub**：`exec/container.rs`（docker/podman）、`ssh.rs`、`singularity.rs`、`openshell.rs` 都只回 `Err("… not implemented yet")`；`session.rs`（持久 shell 狀態）只有 cwd 欄位。
- **未編譯**：`exec/ansi.rs`、`tokenjuice/` 沒有任何 `mod` 宣告（lib.rs、exec/mod.rs 皆無）。
- 沒有新增模型工具 `process`、`terminal`、`read_terminal`、`close_terminal`、`execute_code`；`builtin_tools()` 只多了 `ApplyPatch`。

## 狀態統計

| ✅ | 🚧 | ⬜ | N/A | 合計 |
|---|---|---|---|---|
| 17 | 29 | 15 | 1 | 62 |

（重複的上游列合併成一列，來源欄列出全部出處。✅ 是暫定的，依引用的測試名判定，編譯/測試結果見檔頭。）

## 逐列狀態

| 項目 | 上游來源 | 狀態 | 證據或缺口 |
|---|---|---|---|
| 單一 ExecBackend 抽象 | brief；Hermes tools/environments/*；OC src/agents/sandbox | 🚧 | `seagent-core/src/exec.rs` trait + `exec/mod.rs::build_backend/ExecEnv::backend`，測試 `provider_registry_and_quoting`、`config_defaults_and_validation`；shell/job/run 都沒用它，沒有 `install()` 呼叫，`[exec]` 讀不到 |
| terminal：PTY | Hermes terminal_tool.py；OC exec pty | 🚧 | `exec/local.rs::open_pty/spawn_command`，測試 `pty_is_a_terminal_and_resizes`；`shell` 工具沒有 pty 參數，也不經過 backend |
| terminal：背景早返回 / yieldMs / background | Hermes terminal_background；OC exec yieldMs/background | 🚧 | 只有 `ExecConfig.yield_ms/foreground_max_timeout` 欄位與 `spawn_detached` 原語（測試 `kill_and_detached_survival_files`）；工具端沒有實作。基線 `shell` 只保證背景子行程不擋回傳（`background_process_does_not_block_return`） |
| process：write/submit/send-keys/paste/close/clear/remove/handoff | Hermes process_registry.py；OC bash-tools.process.ts | 🚧 | 只有 `ExecChild::write_stdin` 原語（local.rs，測試 `local_merged_output_exit_and_stdin`）；`job` 沒有這些 action，也沒有 `process` 工具 |
| 持久 cwd/export（local session snapshot） | Hermes environments/local.py | 🚧 | `exec/session.rs` 是 stub（只存 cwd），`ExecEnv::shell` 沒人呼叫；`shell` 每次開新 bash |
| ANSI 去除 | Hermes ansi_strip.py（§1/§6） | 🚧 | `exec/ansi.rs` 完整但未追蹤、未 `mod`，不會編譯；只有 extract/lint 內部的 `extract::strip_ansi` 用於 lint 輸出；shell 輸出不去除 |
| sudo 密碼管線 | Hermes terminal_sudo | ⬜ | 只有 `ExecConfig.sudo_password_secret` 欄位，沒有改寫/餵密碼的程式碼 |
| 失敗輸出提示 | Hermes terminal_hints.py（§1/§6） | ⬜ | 只有 `failure_hints` 欄位 |
| 工具輸出上限／頭尾截斷 | Hermes tool_output_limits.py；OC tool-result-limits.ts | ✅ | 基線 `shell.rs` 截斷，測試 `output_is_capped_head_and_tail` |
| 大結果存檔（spill） | Hermes tool_result_storage.py | ✅ | kernel runner spill，測試 `seagent-kernel/tests/runner.rs::secrets_are_redacted_and_large_output_spilled` |
| read_terminal / close_terminal | Hermes terminal 工具組 | ⬜ | 沒有工具 |
| process：list/poll/log/wait/kill | Hermes process_manage；OC process | ✅ | 基線 `job`（start/output/wait/kill/list），測試 `start_poll_wait_kill_and_isolation` |
| process：200KB 滾動緩衝 | Hermes process_registry.py | 🚧 | `job` 存完整記錄檔並取尾端（`large_output_is_tailed_and_secrets_substituted`）；`process_buffer_bytes` 設定沒人用 |
| 背景行程完成通知 | Hermes process_manage notify | ⬜ | 只有 `ExecEnv::Notifier` 型別，從未安裝或觸發 |
| 背景行程跨重啟保存 | Hermes process_manage | 🚧 | `local.rs::pid_alive/proc_start_time` + detach 的 log/exit 檔（`kill_and_detached_survival_files`）；`job` 沒用，也沒有重啟後恢復 |
| read_file 文件抽取（PDF/DOCX/XLSX/PPTX/ipynb/RTF/ODF/EPUB/sqlite） | Hermes read_extract.py | ✅ | `extract.rs` 經 `fs.rs::read_document`；測試 `docx_paragraphs_breaks_and_ruby`、`xlsx_shared_strings_types_and_hidden_sheets`、`pptx_odf_epub`、`rtf_text`、`notebook_cells_and_outputs`、`pdf_content_streams_and_coverage`、`read_char_budget_and_documents_and_images` |
| read_file 相似檔名建議 | Hermes file_tools.py | ✅ | `filestate::similar_files`（fs.rs:89），測試 `containment_and_suggestions`、`read_failures` |
| 讀取追蹤／重複讀去重／過期寫入警告 | Hermes file_tools_read_tracking.py（§1/§6） | ✅ | `filestate::{record_read,dedup_check,check_stale,stale_overwrite_blocker}`；測試 `read_guards_suggestions_dedup_and_loops`、`baselines_from_full_or_contiguous_reads`、`dedup_stub_then_block_and_consecutive`、`write_guards_stale_and_lint`（只用預設值，`[files]` 不能設定） |
| write_file 寫入守衛（敏感路徑、二進位文件、受保護指令檔） | Hermes file_tools_write_guards.py, file_safety.py | ✅ | `fs.rs::write_guards` + `filestate::sensitive_write_error` 等；測試 `guards`、`write_guards_stale_and_lint`、`write_failures` |
| write_file 寫後 lint | Hermes file_operations_lint.py | ✅ | `lint.rs`（JSON/TOML 在行程內解析，YAML/Python/JS/TS/Go/Rust 走外部 linter）；測試 `json_toml_in_process`、`python_and_yaml_via_interpreter`、`delta_filters_preexisting_and_shell_skips` |
| patch 9 種模糊比對策略 | Hermes fuzzy_match.py | ✅ | `fuzzy.rs::STRATEGIES`（9 個）經 `fs.rs::apply_edit`；測試 `edit_fuzzy_and_hints`、`line_trimmed_and_reindent`、`whitespace_normalized`、`similarity_strategies` 等 |
| patch V4A 格式 | Hermes patch_parser.py | ✅ | `patchfmt::parse_v4a/apply_v4a` 經 `Patch`；測試 `patch_v4a_text`、`v4a_parse_and_apply_all_ops`、`v4a_validation_is_all_or_nothing` |
| 跳脫字元漂移修正 | Hermes escape_drift_autocorrect.py | ✅ | `fuzzy::correct_escape_drift`（由 `fuzzy_replace` 呼叫）；測試 `escape_drift_corrections_and_guards` |
| search_files context/offset/output_mode/order | Hermes file_operations_search.py | ✅ | `search.rs` grep `output_mode/context/before/after/offset`、glob `order/offset/limit`、重複搜尋護欄；測試 `grep_modes_context_offset_and_guards`、`glob_order_and_paging` |
| 跨代理檔案狀態協調 | Hermes file_state.py | ✅ | `filestate` registry + `lock_path`；測試 `sibling_writes_and_blind_patches`、`path_lock_serializes` |
| execute_code 常駐 kernel／reset | Hermes code_kernel.py | ⬜ | `coderun.rs` 未改，每次新行程 |
| execute_code 遠端後端 | Hermes code_execution_tool.py | ⬜ | coderun 不經過 ExecBackend |
| execute_code env 清洗 | Hermes code_execution_env.py | ⬜ | coderun 未改；`sandbox.rs::sanitize_forwarded` 存在但沒人呼叫 |
| execute_code 呼叫預算 | Hermes code_execution_rpc.py | ⬜ | 沒有 |
| PTY 查詢回應 | Hermes pty_query_responder.py | ⬜ | 沒有 |
| hook 輸出溢出存檔 | Hermes hook_output_spill.py | ⬜ | `seagent-kernel/src/hooks.rs` 未改 |
| 本機 OS 沙箱（bubblewrap / Landlock，網路命名空間） | brief；OC sandbox | 🚧 | `local.rs::BwrapBackend/LandlockBackend`，測試 `bwrap_hides_home_and_blocks_network`（**實測失敗：沙箱內仍有網路路由**）、`landlock_restricts_writes_and_home`（通過）；未接上任何工具，沒有 seccomp |
| docker 後端（強化、egress 代理） | Hermes environments/docker.py, docker_egress.py；OC sandbox/docker*.ts | 🚧 | `exec/container.rs` stub：`ContainerBackend::new` 回 `Err("container backend not implemented yet")`；沒有 cap-drop/PID 限制/egress 代理 |
| podman 後端 | OC podman-runtime.ts | 🚧 | 同上 stub |
| ssh 後端 | Hermes environments/ssh.py；OC ssh-backend.ts | 🚧 | `exec/ssh.rs` stub，回 Err |
| modal 後端（managed_modal N/A：Nous 訂閱） | Hermes environments/modal.py | 🚧 | `modal.rs` 透過 Python bridge 驅動 modal SDK，用假 SDK 測試 `bridge_lifecycle_exec_stdin_sync_snapshot`；未接上 |
| daytona 後端 | Hermes environments/daytona.py | 🚧 | `daytona.rs` 真的 REST（`/sandbox`、`/process/session`…），假伺服器測試 `create_exec_stream_sync_and_cleanup`、`missing_key_and_bad_config`；未接上 |
| singularity/apptainer 後端 | Hermes environments/singularity.py | 🚧 | `exec/singularity.rs` stub，回 Err |
| vercel_sandbox 後端 | Hermes environments/vercel_sandbox.py | 🚧 | `vercel.rs` 真的 REST + 假伺服器測試 `create_run_logs_sync_snapshot_restore`、`needs_token`；未接上 |
| OpenShell 後端 | OC extensions/openshell | 🚧 | `exec/openshell.rs` stub，回 Err |
| MXC 後端 | OC extensions/mxc | N/A | 只有 Windows 的 ProcessContainer |
| 外掛執行環境 provider | Hermes agent/terminal_env_provider.py | 🚧 | `exec::register_provider`，測試 `provider_registry_and_quoting`；seagent-plugin 沒有註冊點，整個 ExecEnv 也沒接上 |
| 遠端檔案同步／憑證檔直通 | Hermes file_sync.py, credential_files.py | 🚧 | `sync.rs`，測試 `push_pull_mirror_raw`、`push_pull_mirror_base64`、`credential_files_land_under_remote_home`、`tar_roundtrip_with_long_names_and_links`；只有雲端後端用，而雲端後端本身沒接上 |
| 沙箱模式 off/non-main/all | OC sandbox/types.ts | 🚧 | `ExecEnv::sandboxed`，測試 `sandbox_mode_selects_per_session`；沒有裝 main-session 分類器，設定讀不到 |
| 沙箱範圍 session/agent/shared | OC sandbox/types.ts | 🚧 | `ExecEnv::scope_key`（同一測試）；未接上 |
| 工作區存取 none/ro/rw | OC sandbox/config.ts | 🚧 | `SandboxConfig.workspace_access` + bwrap 掛載，測試 `wrapper_enforces_policy_and_workspace_access`；未接上 |
| 沙箱工具政策 | OC sandbox-tool-policy.ts | 🚧 | `sandbox.rs::ToolPolicy` + `Sandboxed`/`wrap_all`，測試 `tool_policy_defaults_and_overrides`；`wrap_all` 沒人呼叫 |
| 沙箱 env 清洗／掛載安全驗證 | OC sanitize-env-vars.ts, validate-sandbox-security.ts | 🚧 | `sandbox.rs::sanitize_forwarded/validate_bind_source`，測試 `env_scrub_and_forward_rules`、`dangerous_binds_refused`；未接上 |
| 工作區 FS 政策／路徑限制 | OC tool-fs-policy.ts, workspace-file-mutation-guard.ts | 🚧 | `filestate::contain` + `fs::contained`（測試 `apply_patch_tool_and_containment`、`containment_and_suggestions`）；apply_patch 預設限制在工作區，但 `workspace_only` 預設 false，`configure_files` 沒人呼叫，使用者打不開 |
| exec 主機路由 sandbox/gateway/node | OC bash-tools.exec-*.ts | 🚧 | `ExecEnv::sandboxed` + `SessionOverride.host`，未接上；node 仍只能走 `node_invoke system.run` |
| exec elevated（逃出沙箱） | OC exec elevated、/elevated | 🚧 | `ExecEnv::backend(.., elevated)`、`SandboxConfig.elevated`，未接上；沒有 `/elevated` 指令 |
| exec env 參數 | OC exec env | 🚧 | `ExecRequest.env`、`ExecConfig.env`/`child_env`，未接上；`shell` schema 沒有 env |
| ls | OC tool-catalog | ✅ | 基線 `read` 列目錄，測試 `read_dir_and_empty_and_non_utf8` |
| read（圖片／PDF 給模型） | OC agent-tools.read.ts | ✅ | `fs.rs::read_image` 標記 → `kernel.rs` 轉 `Block::Image`；PDF 經 extract；測試 `read_char_budget_and_documents_and_images`、`markers_attach_only_real_images` |
| write / edit | OC tool-catalog | ✅ | 測試 `write_creates_dirs_and_reports_effects`、`edit_paths`、`edit_fuzzy_and_hints` |
| apply_patch（Codex `*** Begin Patch`，add/update/delete/move，限制路徑） | OC apply-patch*.ts | ✅ | `fs.rs::ApplyPatch` 已註冊在 `builtin_tools()`，`patchfmt::parse_apply_patch`；測試 `apply_patch_tool_and_containment`、`apply_patch_add_update_delete_move`、`apply_patch_errors_eof_and_ambiguity` |
| code_execution（xAI 託管） | OC extensions/xai | ⬜ | 沒有 |
| tokenjuice（壓縮 exec 結果） | OC extensions/tokenjuice | 🚧 | 只有未追蹤、未 `mod` 的 `tokenjuice/json.rs`（JS 語意 JSON 值），沒有 reducer，不會編譯 |
| sandbox list/recreate/explain CLI | OC sandbox-cli.ts | ⬜ | 沒有 CLI（只有 `ExecEnv::live_backends/release` 輔助函式） |
| /worktree 斜線指令 | Hermes commands.py | ⬜ | repo 內沒有任何 worktree 程式碼 |
| worktree CLI（list/prune/restore；git worktree 管理） | Hermes worktree_cmd.py, worktree_*.py（§9/§23）；OC worktrees-cli.ts | ⬜ | 沒有 |
| session／子代理 worktree 隔離 | Hermes subagent_worktree.py（§15）；OC src/agents/worktrees（§8） | ⬜ | 沒有 |

## 剩餘缺口（依使用者影響排序）

1. 🚧 **ExecBackend 抽象沒接上**：`shell`/`job`/`run` 仍直接起 bash；需要在 binary 讀 `[exec]`、`exec::install`、改 shell/job/coderun 走 `ExecEnv::backend`，下面所有後端/沙箱列才算上線。
2. 🚧 **沙箱模式 off/non-main/all**：邏輯有了，但沒有 main-session 分類器、沒有設定入口、沒有工具包裝（`wrap_all` 沒呼叫）。
3. 🚧 **docker 後端**：stub，缺容器建立/掛載/使用者/cap-drop/PID 限制/egress 代理/prune。
4. 🚧 **process 互動（write/submit/send-keys/paste/close/clear/remove/handoff）**：只有 `write_stdin` 原語，沒有 `process` 工具或 job action。
5. 🚧 **背景早返回／yieldMs**：只有設定欄位，工具端沒實作。
6. 🚧 **PTY**：backend 支援，`shell` 沒有 pty 參數。
7. 🚧 **持久 cwd/export**：`session.rs` 是 stub。
8. 🚧 **本機 OS 沙箱 bwrap/landlock**：已實作，但 bwrap 網路隔離測試失敗；沒有工具使用；沒有 seccomp。
9. 🚧 **工作區存取 none/ro/rw**：沒接上。
10. 🚧 **沙箱工具政策**：`Sandboxed` 包裝沒套用。
11. 🚧 **沙箱 env 清洗／掛載驗證**：沒接上。
12. 🚧 **工作區 FS 政策**：`workspace_only` 打不開（`configure_files` 沒呼叫，`[files]` 讀不到）。
13. ⬜ **背景行程完成通知**：Notifier 從沒安裝。
14. 🚧 **ssh 後端**：stub。
15. 🚧 **podman 後端**：stub。
16. 🚧 **exec 主機路由**：沒接上，沒有 `/exec` 指令。
17. 🚧 **elevated**：沒接上，沒有 `/elevated`。
18. 🚧 **exec env 參數**：shell schema 沒有 env。
19. 🚧 **ANSI 去除**：`ansi.rs` 沒有 `mod`，不會編譯，shell 輸出沒有去除。
20. ⬜ **sudo 管線**：只有設定欄位。
21. ⬜ **失敗輸出提示**：只有設定欄位。
22. ⬜ **execute_code 常駐 kernel/reset**：coderun 未改。
23. ⬜ **execute_code env 清洗**：coderun 不清洗子行程 env。
24. ⬜ **execute_code 遠端後端**：不經 backend。
25. ⬜ **execute_code 呼叫預算**：沒有。
26. ⬜ **session／子代理 worktree 隔離**：沒有。
27. ⬜ **worktree CLI**：沒有。
28. ⬜ **/worktree 斜線指令**：沒有。
29. 🚧 **背景行程跨重啟保存**：只有 detach 原語，job 沒用。
30. 🚧 **process 200KB 滾動緩衝**：設定沒人用。
31. ⬜ **read_terminal/close_terminal**：沒有工具。
32. 🚧 **modal 後端**：程式碼與假 SDK 測試有，沒接上。
33. 🚧 **daytona 後端**：程式碼與假伺服器測試有，沒接上。
34. 🚧 **vercel 後端**：程式碼與假伺服器測試有，沒接上。
35. 🚧 **singularity/apptainer 後端**：stub。
36. 🚧 **OpenShell 後端**：stub。
37. 🚧 **外掛執行環境 provider**：沒有外掛註冊點，ExecEnv 也沒接上。
38. 🚧 **遠端檔案同步／憑證檔**：只供未接上的雲端後端使用。
39. 🚧 **沙箱範圍 session/agent/shared**：沒接上。
40. ⬜ **sandbox list/recreate/explain CLI**：沒有。
41. 🚧 **tokenjuice**：只有 JSON 輔助檔，沒有 reducer，沒有 `mod`。
42. ⬜ **hook 輸出溢出存檔**：hooks.rs 未改。
43. ⬜ **PTY 查詢回應**：沒有。
44. ⬜ **code_execution（xAI 託管）**：沒有。
